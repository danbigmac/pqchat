#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <deque>
#include <unordered_map>
#include <vector>

#include <sqlite3.h>

#include "pqchat/server/server_api.h"

namespace pqchat::server {

class SqliteStore : public IServerApi {
 public:
  static Result<std::unique_ptr<SqliteStore>> Open(
      const std::string& db_path,
      std::string required_registration_token = {});

  ~SqliteStore() override;

  Result<void> RegisterTransportIdentity(
      const protocol::RegisterRequest& request) override;

  Result<protocol::AuthBeginResponse> BeginTransportAuthentication(
      const protocol::AuthBeginRequest& request) override;

  Result<protocol::AuthFinishResponse> FinishTransportAuthentication(
      const protocol::AuthFinishRequest& request) override;

  Result<std::string> AuthenticateSessionToken(
      const std::vector<uint8_t>& session_token) override;

  Result<void> RevokeSessionToken(
      const std::vector<uint8_t>& session_token) override;

  Result<void> PublishBundle(const protocol::PrekeyBundle& bundle) override;

  Result<protocol::PrekeyBundle> AcquireBundleForSession(
      const std::string& user_id) override;

  Result<void> EnqueueEnvelope(const std::string& user_id,
                               protocol::Envelope envelope) override;

  Result<std::vector<protocol::InboxEnvelope>> DrainInbox(
      const std::string& user_id,
      std::optional<uint64_t> ack_up_to_inbox_id = std::nullopt) override;

 private:
  SqliteStore(sqlite3* db, std::string required_registration_token);

  Result<void> InitSchema();
  Result<void> CleanupAuthState(uint64_t now);
  Result<void> EnforceRateLimit(
      std::unordered_map<std::string, std::deque<uint64_t>>* buckets,
      const std::string& user_id,
      uint64_t now,
      size_t max_attempts,
      uint64_t window_seconds,
      const char* error_text);

  Result<std::vector<uint8_t>> HashToken(
      const std::vector<uint8_t>& token) const;
  Result<void> AppendAuthAudit(const std::string& user_id,
                               const std::string& event,
                               const std::string& detail);
  static uint64_t NowUnix();
  static std::string RandomHex(size_t bytes);
  static Result<std::vector<uint8_t>> RandomBytes(size_t bytes);

  sqlite3* db_ = nullptr;
  std::mutex mu_;
  std::vector<uint8_t> token_hmac_secret_;
  std::unordered_map<std::string, std::deque<uint64_t>> auth_begin_attempts_;
  std::unordered_map<std::string, std::deque<uint64_t>> auth_finish_attempts_;
  std::string required_registration_token_;
};

}  // namespace pqchat::server
