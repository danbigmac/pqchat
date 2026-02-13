#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "pqchat/server/server_api.h"
#include "pqchat/server/tcp_wire.h"

namespace pqchat::client {

struct TlsClientConfig {
  bool enabled = false;
  std::string ca_file;
  std::string server_name;
  std::string client_cert_file;
  std::string client_key_file;
};

class TcpServerApi : public server::IServerApi {
 public:
  using SignFn = std::function<Result<std::vector<uint8_t>>(const std::vector<uint8_t>&)>;

  TcpServerApi(std::string host,
               uint16_t port,
               std::string user_id,
               std::vector<uint8_t> transport_auth_public_key,
               SignFn sign_fn,
               TlsClientConfig tls_config = {});

  Result<void> RegisterTransportIdentity(
      const protocol::RegisterRequest& request) override;

  Result<protocol::AuthBeginResponse> BeginTransportAuthentication(
      const protocol::AuthBeginRequest& request) override;

  Result<protocol::AuthFinishResponse> FinishTransportAuthentication(
      const protocol::AuthFinishRequest& request) override;

  Result<std::string> AuthenticateSessionToken(
      const std::vector<uint8_t>& session_token) override;

  Result<void> PublishBundle(const protocol::PrekeyBundle& bundle) override;

  Result<protocol::PrekeyBundle> AcquireBundleForSession(
      const std::string& user_id) override;

  Result<void> EnqueueEnvelope(const std::string& user_id,
                               protocol::Envelope envelope) override;

  Result<std::vector<protocol::Envelope>> DrainInbox(
      const std::string& user_id) override;

 private:
  Result<void> EnsureAuthenticated();

  Result<std::vector<uint8_t>> Request(server::TcpCommand command,
                                       const std::vector<uint8_t>& payload);
  Result<std::vector<uint8_t>> RequestAuthenticated(
      server::TcpCommand command,
      const std::vector<uint8_t>& payload);

  std::string host_;
  uint16_t port_;
  std::string user_id_;
  std::vector<uint8_t> transport_auth_public_key_;
  SignFn sign_fn_;
  TlsClientConfig tls_config_;
  std::vector<uint8_t> session_token_;
  uint64_t session_expires_at_unix_ = 0;
};

}  // namespace pqchat::client
