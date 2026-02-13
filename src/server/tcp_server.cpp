#include "pqchat/server/tcp_server.h"

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "pqchat/protocol/serialization.h"
#include "pqchat/server/tcp_wire.h"

namespace pqchat::server {
namespace {

std::string SslErrorString() {
  unsigned long error = ERR_get_error();
  if (error == 0) {
    return "unknown SSL error";
  }
  char buf[256];
  ERR_error_string_n(error, buf, sizeof(buf));
  return std::string(buf);
}

}  // namespace

TcpServer::TcpServer(IServerApi* api, uint16_t port, TlsServerConfig tls_config)
    : api_(api), port_(port), tls_config_(std::move(tls_config)) {}

Result<void> TcpServer::Run() {
  if (api_ == nullptr) {
    return Result<void>::Err("server api is null");
  }

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tls_ctx(nullptr, SSL_CTX_free);
  if (tls_config_.enabled) {
    SSL_CTX* raw_ctx = SSL_CTX_new(TLS_server_method());
    if (!raw_ctx) {
      return Result<void>::Err("SSL_CTX_new failed: " + SslErrorString());
    }
    tls_ctx.reset(raw_ctx);

#ifdef TLS1_3_VERSION
    if (SSL_CTX_set_min_proto_version(tls_ctx.get(), TLS1_3_VERSION) != 1) {
      return Result<void>::Err("failed to set TLS min version: " + SslErrorString());
    }
#endif

    if (SSL_CTX_use_certificate_file(tls_ctx.get(), tls_config_.cert_file.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
      return Result<void>::Err("failed to load TLS certificate: " + SslErrorString());
    }
    if (SSL_CTX_use_PrivateKey_file(tls_ctx.get(), tls_config_.key_file.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      return Result<void>::Err("failed to load TLS private key: " + SslErrorString());
    }
    if (SSL_CTX_check_private_key(tls_ctx.get()) != 1) {
      return Result<void>::Err("TLS private key does not match certificate");
    }

    if (!tls_config_.client_ca_file.empty()) {
      if (SSL_CTX_load_verify_locations(tls_ctx.get(), tls_config_.client_ca_file.c_str(),
                                        nullptr) != 1) {
        return Result<void>::Err("failed to load client CA file: " + SslErrorString());
      }
    }

    int verify_mode = SSL_VERIFY_NONE;
    if (tls_config_.require_client_cert) {
      verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(tls_ctx.get(), verify_mode, nullptr);
  }

  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    return Result<void>::Err("socket failed: " + std::string(strerror(errno)));
  }

  int opt = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port_);

  if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(listen_fd);
    return Result<void>::Err("bind failed: " + std::string(strerror(errno)));
  }

  if (listen(listen_fd, 64) < 0) {
    close(listen_fd);
    return Result<void>::Err("listen failed: " + std::string(strerror(errno)));
  }

  while (true) {
    int client_fd = accept(listen_fd, nullptr, nullptr);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(listen_fd);
      return Result<void>::Err("accept failed: " + std::string(strerror(errno)));
    }

    std::thread([this, client_fd, ctx = tls_ctx.get()]() {
      std::unique_ptr<SSL, decltype(&SSL_free)> ssl(nullptr, SSL_free);
      if (ctx != nullptr) {
        SSL* raw_ssl = SSL_new(ctx);
        if (raw_ssl == nullptr) {
          close(client_fd);
          return;
        }
        ssl.reset(raw_ssl);
        SSL_set_fd(ssl.get(), client_fd);
        if (SSL_accept(ssl.get()) != 1) {
          SSL_shutdown(ssl.get());
          close(client_fd);
          return;
        }
      }

      HandleConnection(client_fd, ssl.get());
      if (ssl) {
        SSL_shutdown(ssl.get());
      }
      close(client_fd);
    }).detach();
  }
}

Result<void> TcpServer::HandleConnection(int fd, SSL* tls) {
  while (true) {
    auto frame = tls != nullptr ? ReadFrameTls(tls) : ReadFrame(fd);
    if (!frame.ok()) {
      if (frame.error() == "eof") {
        return Result<void>::Ok();
      }
      return Result<void>::Err(frame.error());
    }

    uint32_t command = frame.value().first;
    const auto& payload = frame.value().second;

    auto send_error = [&](const std::string& error) {
      auto err_payload = protocol::SerializeString(error);
      const auto payload =
          err_payload.ok() ? err_payload.value() : std::vector<uint8_t>{};
      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kError), payload);
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kError), payload);
      }
    };

    if (command == static_cast<uint32_t>(TcpCommand::kRegisterTransportIdentity)) {
      auto request = protocol::DeserializeRegisterRequest(payload);
      if (!request.ok()) {
        send_error(request.error());
        continue;
      }
      auto status = api_->RegisterTransportIdentity(request.value());
      if (!status.ok()) {
        send_error(status.error());
        continue;
      }
      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), {});
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), {});
      }
      continue;
    }

    if (command == static_cast<uint32_t>(TcpCommand::kAuthBegin)) {
      auto request = protocol::DeserializeAuthBeginRequest(payload);
      if (!request.ok()) {
        send_error(request.error());
        continue;
      }
      auto response = api_->BeginTransportAuthentication(request.value());
      if (!response.ok()) {
        send_error(response.error());
        continue;
      }
      auto encoded = protocol::SerializeAuthBeginResponse(response.value());
      if (!encoded.ok()) {
        send_error(encoded.error());
        continue;
      }
      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      }
      continue;
    }

    if (command == static_cast<uint32_t>(TcpCommand::kAuthFinish)) {
      auto request = protocol::DeserializeAuthFinishRequest(payload);
      if (!request.ok()) {
        send_error(request.error());
        continue;
      }
      auto response = api_->FinishTransportAuthentication(request.value());
      if (!response.ok()) {
        send_error(response.error());
        continue;
      }
      auto encoded = protocol::SerializeAuthFinishResponse(response.value());
      if (!encoded.ok()) {
        send_error(encoded.error());
        continue;
      }
      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      }
      continue;
    }

    auto authenticated_payload = protocol::DeserializeAuthenticatedPayload(payload);
    if (!authenticated_payload.ok()) {
      send_error(authenticated_payload.error());
      continue;
    }
    auto session_user = api_->AuthenticateSessionToken(
        authenticated_payload.value().session_token);
    if (!session_user.ok()) {
      send_error(session_user.error());
      continue;
    }

    const auto& inner_payload = authenticated_payload.value().payload;

    if (command == static_cast<uint32_t>(TcpCommand::kPublishBundle)) {
      auto bundle = protocol::DeserializePrekeyBundle(inner_payload);
      if (!bundle.ok()) {
        send_error(bundle.error());
        continue;
      }
      if (bundle.value().user_id != session_user.value()) {
        send_error("publish user_id mismatch with authenticated session");
        continue;
      }

      auto status = api_->PublishBundle(bundle.value());
      if (!status.ok()) {
        send_error(status.error());
        continue;
      }
      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), {});
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), {});
      }
      continue;
    }

    if (command == static_cast<uint32_t>(TcpCommand::kAcquireBundle)) {
      auto user = protocol::DeserializeString(inner_payload);
      if (!user.ok()) {
        send_error(user.error());
        continue;
      }

      auto bundle = api_->AcquireBundleForSession(user.value());
      if (!bundle.ok()) {
        send_error(bundle.error());
        continue;
      }

      auto encoded = protocol::SerializePrekeyBundle(bundle.value());
      if (!encoded.ok()) {
        send_error(encoded.error());
        continue;
      }

      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      }
      continue;
    }

    if (command == static_cast<uint32_t>(TcpCommand::kEnqueueEnvelope)) {
      auto request = protocol::DeserializeEnqueueRequest(inner_payload);
      if (!request.ok()) {
        send_error(request.error());
        continue;
      }

      std::string sender;
      if (request.value().envelope.type == protocol::EnvelopeType::kInitial &&
          request.value().envelope.initial.has_value()) {
        sender = request.value().envelope.initial->from_user;
      } else if (request.value().envelope.type == protocol::EnvelopeType::kChat &&
                 request.value().envelope.chat.has_value()) {
        sender = request.value().envelope.chat->from_user;
      } else {
        send_error("invalid envelope sender");
        continue;
      }

      if (sender != session_user.value()) {
        send_error("envelope sender mismatch with authenticated session");
        continue;
      }

      auto status = api_->EnqueueEnvelope(request.value().user_id,
                                          request.value().envelope);
      if (!status.ok()) {
        send_error(status.error());
        continue;
      }

      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), {});
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), {});
      }
      continue;
    }

    if (command == static_cast<uint32_t>(TcpCommand::kDrainInbox)) {
      auto requested_user = protocol::DeserializeString(inner_payload);
      if (!requested_user.ok()) {
        send_error(requested_user.error());
        continue;
      }
      if (requested_user.value() != session_user.value()) {
        send_error("drain user_id mismatch with authenticated session");
        continue;
      }

      auto envelopes = api_->DrainInbox(session_user.value());
      if (!envelopes.ok()) {
        send_error(envelopes.error());
        continue;
      }

      auto encoded = protocol::SerializeEnvelopeVector(envelopes.value());
      if (!encoded.ok()) {
        send_error(encoded.error());
        continue;
      }

      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), encoded.value());
      }
      continue;
    }

    send_error("unknown command");
  }
}

}  // namespace pqchat::server
