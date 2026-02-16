#include "pqchat/server/tcp_server.h"

#include <cerrno>
#include <cctype>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <chrono>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
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

void TrimWindow(std::deque<uint64_t>* bucket, uint64_t now, uint64_t window_seconds) {
  while (!bucket->empty() && bucket->front() + window_seconds <= now) {
    bucket->pop_front();
  }
}

Result<void> CheckAndRecord(std::deque<uint64_t>* bucket,
                            uint64_t now,
                            uint64_t window_seconds,
                            size_t limit,
                            const char* error_text) {
  TrimWindow(bucket, now, window_seconds);
  if (bucket->size() >= limit) {
    return Result<void>::Err(error_text);
  }
  bucket->push_back(now);
  return Result<void>::Ok();
}

std::string PeerAddressString(int fd) {
  sockaddr_storage peer{};
  socklen_t len = sizeof(peer);
  if (getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &len) != 0) {
    return "unknown";
  }

  char host[INET6_ADDRSTRLEN] = {};
  if (peer.ss_family == AF_INET) {
    const auto* addr = reinterpret_cast<const sockaddr_in*>(&peer);
    if (inet_ntop(AF_INET, &addr->sin_addr, host, sizeof(host)) != nullptr) {
      return std::string(host);
    }
  } else if (peer.ss_family == AF_INET6) {
    const auto* addr = reinterpret_cast<const sockaddr_in6*>(&peer);
    if (inet_ntop(AF_INET6, &addr->sin6_addr, host, sizeof(host)) != nullptr) {
      return std::string(host);
    }
  }
  return "unknown";
}

bool IsValidUserIdForRateLimit(const std::string& user_id) {
  if (user_id.empty() || user_id.size() > 64) {
    return false;
  }
  for (unsigned char c : user_id) {
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
        c == '.') {
      continue;
    }
    return false;
  }
  return true;
}

}  // namespace

TcpServer::TcpServer(IServerApi* api,
                     uint16_t port,
                     TlsServerConfig tls_config,
                     PreAuthRateLimitConfig preauth_rate_limit_config,
                     size_t max_active_connections,
                     int client_io_timeout_seconds)
    : api_(api),
      port_(port),
      tls_config_(std::move(tls_config)),
      preauth_rate_limit_config_(std::move(preauth_rate_limit_config)),
      max_active_connections_(max_active_connections),
      client_io_timeout_seconds_(client_io_timeout_seconds) {}

Result<void> TcpServer::Run() {
  if (api_ == nullptr) {
    return Result<void>::Err("server api is null");
  }

  std::shared_ptr<SSL_CTX> tls_ctx;
  if (tls_config_.enabled) {
    SSL_CTX* raw_ctx = SSL_CTX_new(TLS_server_method());
    if (!raw_ctx) {
      return Result<void>::Err("SSL_CTX_new failed: " + SslErrorString());
    }
    tls_ctx = std::shared_ptr<SSL_CTX>(raw_ctx, SSL_CTX_free);

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
    accepted_connections_.fetch_add(1, std::memory_order_relaxed);

    if (max_active_connections_ > 0 &&
        active_connections_.load(std::memory_order_relaxed) >=
            max_active_connections_) {
      close(client_fd);
      continue;
    }

    if (client_io_timeout_seconds_ > 0) {
      timeval timeout{};
      timeout.tv_sec = client_io_timeout_seconds_;
      timeout.tv_usec = 0;
      if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout)) != 0 ||
          setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                     sizeof(timeout)) != 0) {
        close(client_fd);
        continue;
      }
    }

    active_connections_.fetch_add(1, std::memory_order_relaxed);
    const std::string peer_addr = PeerAddressString(client_fd);
    std::thread([this, client_fd, tls_ctx, peer_addr]() {
      struct ActiveConnectionGuard {
        explicit ActiveConnectionGuard(std::atomic<size_t>* counter)
            : counter_(counter) {}
        ~ActiveConnectionGuard() {
          if (counter_ != nullptr) {
            counter_->fetch_sub(1, std::memory_order_relaxed);
          }
        }
        std::atomic<size_t>* counter_ = nullptr;
      } guard(&active_connections_);

      std::unique_ptr<SSL, decltype(&SSL_free)> ssl(nullptr, SSL_free);
      if (tls_ctx) {
        SSL* raw_ssl = SSL_new(tls_ctx.get());
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

      HandleConnection(client_fd, ssl.get(), peer_addr);
      if (ssl) {
        SSL_shutdown(ssl.get());
      }
      close(client_fd);
    }).detach();
  }
}

uint64_t TcpServer::NowUnix() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<void> TcpServer::EnforcePreAuthRateLimit(uint32_t command,
                                                const std::string& peer_addr) {
  const bool is_register =
      command == static_cast<uint32_t>(TcpCommand::kRegisterTransportIdentity);
  const bool is_auth_begin = command == static_cast<uint32_t>(TcpCommand::kAuthBegin);
  const bool is_auth_finish = command == static_cast<uint32_t>(TcpCommand::kAuthFinish);
  if (!is_register && !is_auth_begin && !is_auth_finish) {
    return Result<void>::Ok();
  }

  const uint64_t now = NowUnix();
  std::scoped_lock lock(preauth_rate_mu_);

  auto trim_map = [&](std::unordered_map<std::string, std::deque<uint64_t>>* buckets) {
    for (auto it = buckets->begin(); it != buckets->end();) {
      TrimWindow(&it->second, now, preauth_rate_limit_config_.window_seconds);
      if (it->second.empty()) {
        it = buckets->erase(it);
      } else {
        ++it;
      }
    }
  };
  trim_map(&preauth_register_by_addr_);
  trim_map(&preauth_auth_begin_by_addr_);
  trim_map(&preauth_auth_finish_by_addr_);
  TrimWindow(&preauth_register_global_, now, preauth_rate_limit_config_.window_seconds);
  TrimWindow(&preauth_auth_begin_global_, now, preauth_rate_limit_config_.window_seconds);
  TrimWindow(&preauth_auth_finish_global_, now, preauth_rate_limit_config_.window_seconds);

  if (is_register) {
    auto per_addr = CheckAndRecord(&preauth_register_by_addr_[peer_addr],
                                   now,
                                   preauth_rate_limit_config_.window_seconds,
                                   preauth_rate_limit_config_.register_per_addr,
                                   "register rate limit exceeded (source address)");
    if (!per_addr.ok()) {
      return per_addr;
    }
    return CheckAndRecord(&preauth_register_global_,
                          now,
                          preauth_rate_limit_config_.window_seconds,
                          preauth_rate_limit_config_.register_global,
                          "register rate limit exceeded (global)");
  }
  if (is_auth_begin) {
    auto per_addr = CheckAndRecord(&preauth_auth_begin_by_addr_[peer_addr],
                                   now,
                                   preauth_rate_limit_config_.window_seconds,
                                   preauth_rate_limit_config_.auth_begin_per_addr,
                                   "auth begin rate limit exceeded (source address)");
    if (!per_addr.ok()) {
      return per_addr;
    }
    return CheckAndRecord(&preauth_auth_begin_global_,
                          now,
                          preauth_rate_limit_config_.window_seconds,
                          preauth_rate_limit_config_.auth_begin_global,
                          "auth begin rate limit exceeded (global)");
  }

  auto per_addr = CheckAndRecord(&preauth_auth_finish_by_addr_[peer_addr],
                                 now,
                                 preauth_rate_limit_config_.window_seconds,
                                 preauth_rate_limit_config_.auth_finish_per_addr,
                                 "auth finish rate limit exceeded (source address)");
  if (!per_addr.ok()) {
    return per_addr;
  }
  return CheckAndRecord(&preauth_auth_finish_global_,
                        now,
                        preauth_rate_limit_config_.window_seconds,
                        preauth_rate_limit_config_.auth_finish_global,
                        "auth finish rate limit exceeded (global)");
}

Result<void> TcpServer::EnforcePreAuthUserRateLimit(uint32_t command,
                                                    const std::string& peer_addr,
                                                    const std::string& user_id) {
  const bool is_register =
      command == static_cast<uint32_t>(TcpCommand::kRegisterTransportIdentity);
  const bool is_auth_begin = command == static_cast<uint32_t>(TcpCommand::kAuthBegin);
  const bool is_auth_finish = command == static_cast<uint32_t>(TcpCommand::kAuthFinish);
  if ((!is_register && !is_auth_begin && !is_auth_finish) || !IsValidUserIdForRateLimit(user_id)) {
    return Result<void>::Ok();
  }

  const uint64_t now = NowUnix();
  const std::string key = peer_addr + "|" + user_id;
  std::scoped_lock lock(preauth_rate_mu_);
  auto trim_map = [&](std::unordered_map<std::string, std::deque<uint64_t>>* buckets) {
    for (auto it = buckets->begin(); it != buckets->end();) {
      TrimWindow(&it->second, now, preauth_rate_limit_config_.window_seconds);
      if (it->second.empty()) {
        it = buckets->erase(it);
      } else {
        ++it;
      }
    }
  };

  trim_map(&preauth_register_by_addr_user_);
  trim_map(&preauth_auth_begin_by_addr_user_);
  trim_map(&preauth_auth_finish_by_addr_user_);

  if (is_register) {
    return CheckAndRecord(&preauth_register_by_addr_user_[key],
                          now,
                          preauth_rate_limit_config_.window_seconds,
                          preauth_rate_limit_config_.register_per_addr_user,
                          "register rate limit exceeded (source+user)");
  }
  if (is_auth_begin) {
    return CheckAndRecord(&preauth_auth_begin_by_addr_user_[key],
                          now,
                          preauth_rate_limit_config_.window_seconds,
                          preauth_rate_limit_config_.auth_begin_per_addr_user,
                          "auth begin rate limit exceeded (source+user)");
  }
  return CheckAndRecord(&preauth_auth_finish_by_addr_user_[key],
                        now,
                        preauth_rate_limit_config_.window_seconds,
                        preauth_rate_limit_config_.auth_finish_per_addr_user,
                        "auth finish rate limit exceeded (source+user)");
}

Result<void> TcpServer::HandleConnection(int fd, SSL* tls, const std::string& peer_addr) {
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

    auto preauth_limit = EnforcePreAuthRateLimit(command, peer_addr);
    if (!preauth_limit.ok()) {
      send_error(preauth_limit.error());
      continue;
    }

    if (command == static_cast<uint32_t>(TcpCommand::kRegisterTransportIdentity)) {
      auto request = protocol::DeserializeRegisterRequest(payload);
      if (!request.ok()) {
        send_error(request.error());
        continue;
      }
      auto user_limit = EnforcePreAuthUserRateLimit(command, peer_addr, request.value().user_id);
      if (!user_limit.ok()) {
        send_error(user_limit.error());
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
      auto user_limit = EnforcePreAuthUserRateLimit(command, peer_addr, request.value().user_id);
      if (!user_limit.ok()) {
        send_error(user_limit.error());
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
      auto user_limit = EnforcePreAuthUserRateLimit(command, peer_addr, request.value().user_id);
      if (!user_limit.ok()) {
        send_error(user_limit.error());
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

    if (command == static_cast<uint32_t>(TcpCommand::kLogout)) {
      auto revoked =
          api_->RevokeSessionToken(authenticated_payload.value().session_token);
      if (!revoked.ok()) {
        send_error(revoked.error());
        continue;
      }
      if (tls != nullptr) {
        WriteFrameTls(tls, static_cast<uint32_t>(TcpStatus::kOk), {});
      } else {
        WriteFrame(fd, static_cast<uint32_t>(TcpStatus::kOk), {});
      }
      continue;
    }

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
      std::string recipient;
      if (request.value().envelope.type == protocol::EnvelopeType::kInitial &&
          request.value().envelope.initial.has_value()) {
        sender = request.value().envelope.initial->from_user;
        recipient = request.value().envelope.initial->to_user;
      } else if (request.value().envelope.type == protocol::EnvelopeType::kChat &&
                 request.value().envelope.chat.has_value()) {
        sender = request.value().envelope.chat->from_user;
        recipient = request.value().envelope.chat->to_user;
      } else {
        send_error("invalid envelope sender");
        continue;
      }

      if (sender != session_user.value()) {
        send_error("envelope sender mismatch with authenticated session");
        continue;
      }
      if (recipient != request.value().user_id) {
        send_error("envelope recipient mismatch with enqueue target");
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
      auto drain_request = protocol::DeserializeDrainInboxRequest(inner_payload);
      if (!drain_request.ok()) {
        send_error(drain_request.error());
        continue;
      }
      if (drain_request.value().user_id != session_user.value()) {
        send_error("drain user_id mismatch with authenticated session");
        continue;
      }

      auto envelopes = api_->DrainInbox(session_user.value(),
                                        drain_request.value().ack_up_to_inbox_id);
      if (!envelopes.ok()) {
        send_error(envelopes.error());
        continue;
      }

      auto encoded = protocol::SerializeInboxEnvelopeVector(envelopes.value());
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
