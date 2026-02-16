#include "pqchat/client/tcp_server_api.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "pqchat/protocol/serialization.h"
#include "pqchat/protocol/transport_auth.h"
#include "pqchat/client/tls_pinning.h"
#include "pqchat/server/tcp_wire.h"

namespace pqchat::client {
namespace {

uint64_t NowUnix() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<std::vector<uint8_t>> RandomBytes(size_t len) {
  std::vector<uint8_t> out(len);
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    return Result<std::vector<uint8_t>>::Err("RAND_bytes failed");
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> PeerCertificateSha256(SSL* ssl) {
  if (ssl == nullptr) {
    return Result<std::vector<uint8_t>>::Err("SSL pointer is null");
  }

  X509* raw_cert = SSL_get1_peer_certificate(ssl);
  if (raw_cert == nullptr) {
    return Result<std::vector<uint8_t>>::Err("server did not present a certificate");
  }
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);

  std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
  unsigned int digest_len = 0;
  if (X509_digest(cert.get(), EVP_sha256(), digest.data(), &digest_len) != 1) {
    return Result<std::vector<uint8_t>>::Err("failed computing server cert fingerprint");
  }
  digest.resize(digest_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(digest));
}

Result<int> ConnectTcp(const std::string& host, uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* result = nullptr;
  const std::string port_str = std::to_string(port);
  int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
  if (rc != 0) {
    return Result<int>::Err("getaddrinfo failed: " + std::string(gai_strerror(rc)));
  }

  std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(result, freeaddrinfo);

  for (addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
      continue;
    }

    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
      return Result<int>::Ok(fd);
    }

    close(fd);
  }

  return Result<int>::Err("connect failed: " + std::string(strerror(errno)));
}

std::string SslErrorString() {
  unsigned long error = ERR_get_error();
  if (error == 0) {
    return "unknown SSL error";
  }
  char buf[256];
  ERR_error_string_n(error, buf, sizeof(buf));
  return std::string(buf);
}

Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>> CreateClientTlsContext(
    const TlsClientConfig& config) {
  SSL_CTX* raw = SSL_CTX_new(TLS_client_method());
  if (!raw) {
    return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
        "SSL_CTX_new failed: " + SslErrorString());
  }
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(raw, SSL_CTX_free);

#ifdef TLS1_3_VERSION
  if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
    return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
        "failed to set TLS min version: " + SslErrorString());
  }
#endif

  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

  if (config.ca_file.empty()) {
    if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
      return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
          "failed to load default CA paths: " + SslErrorString());
    }
  } else if (SSL_CTX_load_verify_locations(ctx.get(), config.ca_file.c_str(), nullptr) !=
             1) {
    return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
        "failed to load CA file: " + SslErrorString());
  }

  if (!config.client_cert_file.empty()) {
    if (SSL_CTX_use_certificate_file(ctx.get(), config.client_cert_file.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
      return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
          "failed to load TLS client certificate: " + SslErrorString());
    }
  }
  if (!config.client_key_file.empty()) {
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), config.client_key_file.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
          "failed to load TLS client key: " + SslErrorString());
    }
  }
  if (!config.client_cert_file.empty() || !config.client_key_file.empty()) {
    if (SSL_CTX_check_private_key(ctx.get()) != 1) {
      return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Err(
          "TLS client key does not match certificate");
    }
  }

  return Result<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>>::Ok(std::move(ctx));
}

}  // namespace

TcpServerApi::TcpServerApi(std::string host,
                           uint16_t port,
                           std::string user_id,
                           std::vector<uint8_t> transport_auth_public_key,
                           SignFn sign_fn,
                           std::string registration_token,
                           TlsClientConfig tls_config)
    : host_(std::move(host)),
      port_(port),
      user_id_(std::move(user_id)),
      transport_auth_public_key_(std::move(transport_auth_public_key)),
      sign_fn_(std::move(sign_fn)),
      registration_token_(std::move(registration_token)),
      tls_config_(std::move(tls_config)),
      tls_ctx_(nullptr, SSL_CTX_free),
      tls_ssl_(nullptr, SSL_free) {}

TcpServerApi::~TcpServerApi() {
  CloseConnection();
}

void TcpServerApi::CloseConnection() {
  if (tls_ssl_) {
    SSL_shutdown(tls_ssl_.get());
    tls_ssl_.reset();
  }
  tls_ctx_.reset();
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
}

Result<void> TcpServerApi::EnsureConnected() {
  if (fd_ >= 0) {
    return Result<void>::Ok();
  }

  auto fd_result = ConnectTcp(host_, port_);
  if (!fd_result.ok()) {
    return Result<void>::Err(fd_result.error());
  }
  fd_ = fd_result.take_value();

  if (!tls_config_.enabled) {
    return Result<void>::Ok();
  }

  auto ctx_result = CreateClientTlsContext(tls_config_);
  if (!ctx_result.ok()) {
    CloseConnection();
    return Result<void>::Err(ctx_result.error());
  }
  tls_ctx_ = ctx_result.take_value();

  SSL* raw_ssl = SSL_new(tls_ctx_.get());
  if (!raw_ssl) {
    CloseConnection();
    return Result<void>::Err("SSL_new failed: " + SslErrorString());
  }
  tls_ssl_.reset(raw_ssl);
  SSL_set_fd(tls_ssl_.get(), fd_);

  const std::string verify_name =
      tls_config_.server_name.empty() ? host_ : tls_config_.server_name;
  if (!verify_name.empty()) {
    X509_VERIFY_PARAM* verify_param = SSL_get0_param(tls_ssl_.get());
    in_addr ipv4{};
    in6_addr ipv6{};
    const bool is_ip = inet_pton(AF_INET, verify_name.c_str(), &ipv4) == 1 ||
                       inet_pton(AF_INET6, verify_name.c_str(), &ipv6) == 1;
    if (is_ip) {
      if (X509_VERIFY_PARAM_set1_ip_asc(verify_param, verify_name.c_str()) != 1) {
        CloseConnection();
        return Result<void>::Err("failed to set TLS verify IP");
      }
    } else {
      if (SSL_set_tlsext_host_name(tls_ssl_.get(), verify_name.c_str()) != 1) {
        CloseConnection();
        return Result<void>::Err("failed to set TLS SNI hostname");
      }
      if (X509_VERIFY_PARAM_set1_host(verify_param, verify_name.c_str(), 0) != 1) {
        CloseConnection();
        return Result<void>::Err("failed to set TLS verify hostname");
      }
    }
  }

  if (SSL_connect(tls_ssl_.get()) != 1) {
    const std::string error = "TLS handshake failed: " + SslErrorString();
    CloseConnection();
    return Result<void>::Err(error);
  }

  if (!tls_config_.pinned_server_cert_sha256_hex.empty()) {
    auto fingerprint = PeerCertificateSha256(tls_ssl_.get());
    if (!fingerprint.ok()) {
      CloseConnection();
      return Result<void>::Err(fingerprint.error());
    }
    auto pin_check = VerifyPinnedSha256Fingerprint(
        fingerprint.value(),
        tls_config_.pinned_server_cert_sha256_hex);
    if (!pin_check.ok()) {
      CloseConnection();
      return Result<void>::Err(pin_check.error());
    }
  }

  return Result<void>::Ok();
}

Result<std::vector<uint8_t>> TcpServerApi::Request(server::TcpCommand command,
                                                   const std::vector<uint8_t>& payload) {
  auto connected = EnsureConnected();
  if (!connected.ok()) {
    return Result<std::vector<uint8_t>>::Err(connected.error());
  }

  Result<std::pair<uint32_t, std::vector<uint8_t>>> response =
      Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err("request failed");
  if (tls_config_.enabled) {
    auto write = server::WriteFrameTls(tls_ssl_.get(), static_cast<uint32_t>(command), payload);
    if (!write.ok()) {
      CloseConnection();
      return Result<std::vector<uint8_t>>::Err(write.error());
    }
    response = server::ReadFrameTls(tls_ssl_.get());
  } else {
    auto write = server::WriteFrame(fd_, static_cast<uint32_t>(command), payload);
    if (!write.ok()) {
      CloseConnection();
      return Result<std::vector<uint8_t>>::Err(write.error());
    }
    response = server::ReadFrame(fd_);
  }

  if (!response.ok()) {
    CloseConnection();
    return Result<std::vector<uint8_t>>::Err(response.error());
  }

  uint32_t status = response.value().first;
  const auto& response_payload = response.value().second;
  if (status == static_cast<uint32_t>(server::TcpStatus::kOk)) {
    return Result<std::vector<uint8_t>>::Ok(response_payload);
  }

  auto error_message = protocol::DeserializeString(response_payload);
  if (!error_message.ok()) {
    return Result<std::vector<uint8_t>>::Err("server returned error");
  }
  return Result<std::vector<uint8_t>>::Err(error_message.value());
}

Result<std::vector<uint8_t>> TcpServerApi::RequestAuthenticated(
    server::TcpCommand command,
    const std::vector<uint8_t>& payload) {
  protocol::AuthenticatedPayload authenticated;
  authenticated.session_token = session_token_;
  authenticated.payload = payload;

  auto encoded = protocol::SerializeAuthenticatedPayload(authenticated);
  if (!encoded.ok()) {
    return Result<std::vector<uint8_t>>::Err(encoded.error());
  }
  return Request(command, encoded.value());
}

Result<void> TcpServerApi::EnsureAuthenticated() {
  if (!sign_fn_) {
    return Result<void>::Err("transport auth signer is not configured");
  }

  if (!session_token_.empty() && NowUnix() + 5 < session_expires_at_unix_) {
    return Result<void>::Ok();
  }

  protocol::RegisterRequest register_request;
  register_request.user_id = user_id_;
  register_request.transport_auth_public_key = transport_auth_public_key_;
  register_request.registration_token = registration_token_;
  auto register_sign_input = protocol::BuildTransportRegisterSignInput(
      user_id_,
      transport_auth_public_key_);
  auto register_signature = sign_fn_(register_sign_input);
  if (!register_signature.ok()) {
    return Result<void>::Err(register_signature.error());
  }
  register_request.proof_signature_mldsa65 = register_signature.take_value();
  register_request.rotation_signature_mldsa65 = std::nullopt;
  auto register_status = RegisterTransportIdentity(register_request);
  if (!register_status.ok()) {
    return register_status;
  }

  auto client_nonce = RandomBytes(32);
  if (!client_nonce.ok()) {
    return Result<void>::Err(client_nonce.error());
  }

  protocol::AuthBeginRequest begin_request;
  begin_request.user_id = user_id_;
  begin_request.client_nonce = client_nonce.take_value();

  auto begin_response = BeginTransportAuthentication(begin_request);
  if (!begin_response.ok()) {
    return Result<void>::Err(begin_response.error());
  }

  auto sign_input = protocol::BuildTransportAuthSignInput(
      user_id_,
      begin_request.client_nonce,
      begin_response.value().server_nonce,
      begin_response.value().challenge_id,
      begin_response.value().expires_at_unix);

  auto signature = sign_fn_(sign_input);
  if (!signature.ok()) {
    return Result<void>::Err(signature.error());
  }

  protocol::AuthFinishRequest finish_request;
  finish_request.user_id = user_id_;
  finish_request.challenge_id = begin_response.value().challenge_id;
  finish_request.client_nonce = begin_request.client_nonce;
  finish_request.server_nonce = begin_response.value().server_nonce;
  finish_request.expires_at_unix = begin_response.value().expires_at_unix;
  finish_request.signature_mldsa65 = signature.take_value();

  auto finish_response = FinishTransportAuthentication(finish_request);
  if (!finish_response.ok()) {
    return Result<void>::Err(finish_response.error());
  }

  session_token_ = finish_response.value().session_token;
  session_expires_at_unix_ = finish_response.value().expires_at_unix;

  return Result<void>::Ok();
}

Result<void> TcpServerApi::RegisterTransportIdentity(
    const protocol::RegisterRequest& request) {
  auto payload = protocol::SerializeRegisterRequest(request);
  if (!payload.ok()) {
    return Result<void>::Err(payload.error());
  }

  auto response = Request(server::TcpCommand::kRegisterTransportIdentity,
                          payload.value());
  if (!response.ok()) {
    return Result<void>::Err(response.error());
  }
  return Result<void>::Ok();
}

Result<protocol::AuthBeginResponse> TcpServerApi::BeginTransportAuthentication(
    const protocol::AuthBeginRequest& request) {
  auto payload = protocol::SerializeAuthBeginRequest(request);
  if (!payload.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(payload.error());
  }

  auto response = Request(server::TcpCommand::kAuthBegin, payload.value());
  if (!response.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(response.error());
  }

  return protocol::DeserializeAuthBeginResponse(response.value());
}

Result<protocol::AuthFinishResponse> TcpServerApi::FinishTransportAuthentication(
    const protocol::AuthFinishRequest& request) {
  auto payload = protocol::SerializeAuthFinishRequest(request);
  if (!payload.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(payload.error());
  }

  auto response = Request(server::TcpCommand::kAuthFinish, payload.value());
  if (!response.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(response.error());
  }

  return protocol::DeserializeAuthFinishResponse(response.value());
}

Result<std::string> TcpServerApi::AuthenticateSessionToken(
    const std::vector<uint8_t>& /*session_token*/) {
  return Result<std::string>::Err("not supported on client adapter");
}

Result<void> TcpServerApi::RevokeSessionToken(
    const std::vector<uint8_t>& session_token) {
  protocol::AuthenticatedPayload authenticated;
  authenticated.session_token = session_token;
  authenticated.payload = {};
  auto encoded = protocol::SerializeAuthenticatedPayload(authenticated);
  if (!encoded.ok()) {
    return Result<void>::Err(encoded.error());
  }
  auto response = Request(server::TcpCommand::kLogout, encoded.value());
  if (!response.ok()) {
    return Result<void>::Err(response.error());
  }
  if (session_token_ == session_token) {
    session_token_.clear();
    session_expires_at_unix_ = 0;
  }
  CloseConnection();
  return Result<void>::Ok();
}

Result<void> TcpServerApi::LogoutCurrentSession() {
  auto auth = EnsureAuthenticated();
  if (!auth.ok()) {
    return Result<void>::Err(auth.error());
  }
  return RevokeSessionToken(session_token_);
}

Result<void> TcpServerApi::PublishBundle(const protocol::PrekeyBundle& bundle) {
  auto auth = EnsureAuthenticated();
  if (!auth.ok()) {
    return Result<void>::Err(auth.error());
  }

  auto payload = protocol::SerializePrekeyBundle(bundle);
  if (!payload.ok()) {
    return Result<void>::Err(payload.error());
  }

  auto response = RequestAuthenticated(server::TcpCommand::kPublishBundle,
                                       payload.value());
  if (!response.ok()) {
    return Result<void>::Err(response.error());
  }
  return Result<void>::Ok();
}

Result<protocol::PrekeyBundle> TcpServerApi::AcquireBundleForSession(
    const std::string& user_id) {
  auto auth = EnsureAuthenticated();
  if (!auth.ok()) {
    return Result<protocol::PrekeyBundle>::Err(auth.error());
  }

  auto payload = protocol::SerializeString(user_id);
  if (!payload.ok()) {
    return Result<protocol::PrekeyBundle>::Err(payload.error());
  }

  auto response = RequestAuthenticated(server::TcpCommand::kAcquireBundle,
                                       payload.value());
  if (!response.ok()) {
    return Result<protocol::PrekeyBundle>::Err(response.error());
  }

  return protocol::DeserializePrekeyBundle(response.value());
}

Result<void> TcpServerApi::EnqueueEnvelope(const std::string& user_id,
                                           protocol::Envelope envelope) {
  auto auth = EnsureAuthenticated();
  if (!auth.ok()) {
    return Result<void>::Err(auth.error());
  }

  protocol::EnqueueRequest request{user_id, std::move(envelope)};
  auto payload = protocol::SerializeEnqueueRequest(request);
  if (!payload.ok()) {
    return Result<void>::Err(payload.error());
  }

  auto response = RequestAuthenticated(server::TcpCommand::kEnqueueEnvelope,
                                       payload.value());
  if (!response.ok()) {
    return Result<void>::Err(response.error());
  }
  return Result<void>::Ok();
}

Result<std::vector<protocol::InboxEnvelope>> TcpServerApi::DrainInbox(
    const std::string& user_id,
    std::optional<uint64_t> ack_up_to_inbox_id) {
  auto auth = EnsureAuthenticated();
  if (!auth.ok()) {
    return Result<std::vector<protocol::InboxEnvelope>>::Err(auth.error());
  }

  protocol::DrainInboxRequest request;
  request.user_id = user_id;
  request.ack_up_to_inbox_id = ack_up_to_inbox_id;
  auto payload = protocol::SerializeDrainInboxRequest(request);
  if (!payload.ok()) {
    return Result<std::vector<protocol::InboxEnvelope>>::Err(payload.error());
  }

  auto response = RequestAuthenticated(server::TcpCommand::kDrainInbox,
                                       payload.value());
  if (!response.ok()) {
    return Result<std::vector<protocol::InboxEnvelope>>::Err(response.error());
  }

  return protocol::DeserializeInboxEnvelopeVector(response.value());
}

}  // namespace pqchat::client
