#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "pqchat/server/server_api.h"

namespace pqchat::server {

class SqliteStore : public IServerApi {
 public:
  static Result<std::unique_ptr<SqliteStore>> Open(const std::string& db_path);

  ~SqliteStore() override;

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
  explicit SqliteStore(sqlite3* db);

  Result<void> InitSchema();

  Result<std::vector<uint8_t>> HashToken(
      const std::vector<uint8_t>& token) const;
  static uint64_t NowUnix();
  static std::string RandomHex(size_t bytes);
  static Result<std::vector<uint8_t>> RandomBytes(size_t bytes);

  sqlite3* db_ = nullptr;
  std::mutex mu_;
  std::vector<uint8_t> token_hmac_secret_;
};

}  // namespace pqchat::server
