#pragma once

#include <optional>
#include <string>
#include <vector>

#include "pqchat/protocol/messages.h"
#include "pqchat/protocol/prekey_bundle.h"
#include "pqchat/protocol/transport_auth.h"
#include "pqchat/util/result.h"

namespace pqchat::server {

class IServerApi {
 public:
  virtual ~IServerApi() = default;

  virtual Result<void> RegisterTransportIdentity(
      const protocol::RegisterRequest& request) = 0;

  virtual Result<protocol::AuthBeginResponse> BeginTransportAuthentication(
      const protocol::AuthBeginRequest& request) = 0;

  virtual Result<protocol::AuthFinishResponse> FinishTransportAuthentication(
      const protocol::AuthFinishRequest& request) = 0;

  virtual Result<std::string> AuthenticateSessionToken(
      const std::vector<uint8_t>& session_token) = 0;

  virtual Result<void> RevokeSessionToken(
      const std::vector<uint8_t>& session_token) = 0;

  virtual Result<void> PublishBundle(const protocol::PrekeyBundle& bundle) = 0;

  virtual Result<protocol::PrekeyBundle> AcquireBundleForSession(
      const std::string& user_id) = 0;

  virtual Result<void> EnqueueEnvelope(const std::string& user_id,
                                       protocol::Envelope envelope) = 0;

  virtual Result<std::vector<protocol::InboxEnvelope>> DrainInbox(
      const std::string& user_id,
      std::optional<uint64_t> ack_up_to_inbox_id = std::nullopt) = 0;
};

}  // namespace pqchat::server
