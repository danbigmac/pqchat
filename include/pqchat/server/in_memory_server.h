#pragma once

#include <deque>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "pqchat/protocol/messages.h"
#include "pqchat/protocol/prekey_bundle.h"
#include "pqchat/server/server_api.h"
#include "pqchat/util/result.h"

namespace pqchat::server {

class InMemoryServer : public IServerApi {
 public:
  InMemoryServer() = default;

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
  struct BundleStore {
    protocol::PrekeyBundle base_bundle;
    std::vector<protocol::OneTimePrekeyEc> one_time_ec_pool;
    std::vector<protocol::OneTimePrekeyPq> one_time_pq_pool;
  };

  struct ChallengeState {
    std::string user_id;
    std::vector<uint8_t> client_nonce;
    std::vector<uint8_t> server_nonce;
    uint64_t expires_at_unix = 0;
    bool used = false;
  };

  struct SessionState {
    std::string user_id;
    uint64_t expires_at_unix = 0;
  };

  static uint64_t NowUnix();
  static std::string RandomHex(size_t bytes);
  static std::vector<uint8_t> RandomBytes(size_t bytes);

  std::mutex mu_;
  std::unordered_map<std::string, BundleStore> bundles_;
  std::unordered_map<std::string, std::deque<protocol::Envelope>> inbox_;
  std::unordered_map<std::string, std::vector<uint8_t>> transport_identities_;
  std::unordered_map<std::string, ChallengeState> challenges_;
  std::unordered_map<std::string, SessionState> sessions_;
};

}  // namespace pqchat::server
