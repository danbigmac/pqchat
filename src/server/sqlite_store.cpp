#include "pqchat/server/sqlite_store.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/protocol/serialization.h"
#include "pqchat/protocol/transport_auth.h"

namespace pqchat::server {
namespace {

using StmtPtr = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

constexpr size_t kMaxUserIdBytes = 64;
constexpr size_t kMaxTransportAuthPublicKeyBytes = 8192;
constexpr size_t kExpectedAuthNonceBytes = 32;
constexpr size_t kExpectedSessionTokenBytes = 32;
constexpr size_t kMinMlDsaSignatureBytes = 64;
constexpr size_t kMaxMlDsaSignatureBytes = 8192;
constexpr size_t kChallengeIdHexBytes = 32;
constexpr size_t kMaxDrainInboxBatchItems = 128;
constexpr size_t kMaxDrainInboxBatchBytes = 512 * 1024;
constexpr uint64_t kAuthRateWindowSeconds = 60;
constexpr size_t kMaxAuthBeginAttemptsPerWindow = 30;
constexpr size_t kMaxAuthFinishAttemptsPerWindow = 30;

bool IsValidUserId(const std::string& user_id) {
  if (user_id.empty() || user_id.size() > kMaxUserIdBytes) {
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

int HexValue(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

bool IsValidHexString(const std::string& value) {
  for (char c : value) {
    if (HexValue(c) < 0) {
      return false;
    }
  }
  return true;
}

bool IsValidChallengeId(const std::string& challenge_id) {
  return challenge_id.size() == kChallengeIdHexBytes &&
         IsValidHexString(challenge_id);
}

Result<std::vector<uint8_t>> DecodeHex(const std::string& hex) {
  if ((hex.size() % 2) != 0) {
    return Result<std::vector<uint8_t>>::Err("invalid hex length");
  }

  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = HexValue(hex[i]);
    int lo = HexValue(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return Result<std::vector<uint8_t>>::Err("invalid hex character");
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<void> VerifyProvisioningToken(const std::string& provisioning_secret,
                                     const std::string& user_id,
                                     const std::string& token_hex) {
  auto expected = crypto::HmacSha256(crypto::ToBytes(provisioning_secret),
                                     crypto::ToBytes(user_id));
  if (!expected.ok()) {
    return Result<void>::Err("failed to derive registration token");
  }

  const auto& expected_bytes = expected.value();
  if (token_hex.size() != expected_bytes.size() * 2) {
    return Result<void>::Err("invalid registration token");
  }

  auto provided = DecodeHex(token_hex);
  if (!provided.ok()) {
    return Result<void>::Err("invalid registration token");
  }

  const auto& provided_bytes = provided.value();
  if (expected_bytes.size() != provided_bytes.size()) {
    return Result<void>::Err("invalid registration token");
  }
  if (CRYPTO_memcmp(expected_bytes.data(),
                    provided_bytes.data(),
                    expected_bytes.size()) != 0) {
    return Result<void>::Err("invalid registration token");
  }

  return Result<void>::Ok();
}

Result<void> Exec(sqlite3* db, const char* sql) {
  char* errmsg = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
    std::string message = errmsg ? errmsg : "sqlite3_exec failed";
    sqlite3_free(errmsg);
    return Result<void>::Err(message);
  }
  return Result<void>::Ok();
}

Result<void> ExecAllowingDuplicateColumn(sqlite3* db, const char* sql) {
  auto exec = Exec(db, sql);
  if (exec.ok()) {
    return exec;
  }
  if (exec.error().find("duplicate column name") != std::string::npos) {
    return Result<void>::Ok();
  }
  return exec;
}

Result<StmtPtr> Prepare(sqlite3* db, const char* sql) {
  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return Result<StmtPtr>::Err(sqlite3_errmsg(db));
  }
  return Result<StmtPtr>::Ok(StmtPtr(stmt, sqlite3_finalize));
}

Result<void> BindText(sqlite3_stmt* stmt, int index, const std::string& value) {
  if (sqlite3_bind_text(stmt, index, value.data(), static_cast<int>(value.size()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    return Result<void>::Err("sqlite bind text failed");
  }
  return Result<void>::Ok();
}

Result<void> BindBlob(sqlite3_stmt* stmt, int index, const std::vector<uint8_t>& value) {
  if (sqlite3_bind_blob(stmt, index, value.data(), static_cast<int>(value.size()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    return Result<void>::Err("sqlite bind blob failed");
  }
  return Result<void>::Ok();
}

Result<void> BindU32(sqlite3_stmt* stmt, int index, uint32_t value) {
  if (sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(value)) != SQLITE_OK) {
    return Result<void>::Err("sqlite bind int failed");
  }
  return Result<void>::Ok();
}

Result<void> StepDone(sqlite3* db, sqlite3_stmt* stmt) {
  if (sqlite3_step(stmt) != SQLITE_DONE) {
    return Result<void>::Err(sqlite3_errmsg(db));
  }
  return Result<void>::Ok();
}

std::vector<uint8_t> ColumnBlob(sqlite3_stmt* stmt, int col) {
  const void* data = sqlite3_column_blob(stmt, col);
  int len = sqlite3_column_bytes(stmt, col);
  std::vector<uint8_t> out;
  if (len <= 0) {
    return out;
  }
  out.resize(static_cast<size_t>(len));
  std::memcpy(out.data(), data, static_cast<size_t>(len));
  return out;
}

Result<void> Begin(sqlite3* db) { return Exec(db, "BEGIN IMMEDIATE;"); }
Result<void> Commit(sqlite3* db) { return Exec(db, "COMMIT;"); }
void Rollback(sqlite3* db) {
  Exec(db, "ROLLBACK;");
}

Result<void> InsertOneTimeEc(sqlite3* db,
                             const std::string& user_id,
                             const protocol::OneTimePrekeyEc& key) {
  auto stmt_result = Prepare(db, "INSERT INTO one_time_ec(user_id, key_id, public_key) VALUES(?, ?, ?);");
  if (!stmt_result.ok()) {
    return Result<void>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();

  auto bind_user = BindText(stmt.get(), 1, user_id);
  if (!bind_user.ok()) {
    return bind_user;
  }
  auto bind_id = BindU32(stmt.get(), 2, key.id);
  if (!bind_id.ok()) {
    return bind_id;
  }
  auto bind_key = BindBlob(stmt.get(), 3, key.public_key);
  if (!bind_key.ok()) {
    return bind_key;
  }

  return StepDone(db, stmt.get());
}

Result<void> InsertOneTimePq(sqlite3* db,
                             const std::string& user_id,
                             const protocol::OneTimePrekeyPq& key) {
  auto stmt_result = Prepare(db, "INSERT INTO one_time_pq(user_id, key_id, public_key) VALUES(?, ?, ?);");
  if (!stmt_result.ok()) {
    return Result<void>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();

  auto bind_user = BindText(stmt.get(), 1, user_id);
  if (!bind_user.ok()) {
    return bind_user;
  }
  auto bind_id = BindU32(stmt.get(), 2, key.id);
  if (!bind_id.ok()) {
    return bind_id;
  }
  auto bind_key = BindBlob(stmt.get(), 3, key.public_key);
  if (!bind_key.ok()) {
    return bind_key;
  }

  return StepDone(db, stmt.get());
}

}  // namespace

SqliteStore::SqliteStore(sqlite3* db, std::string required_registration_token)
    : db_(db),
      required_registration_token_(std::move(required_registration_token)) {}

SqliteStore::~SqliteStore() {
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

Result<std::unique_ptr<SqliteStore>> SqliteStore::Open(
    const std::string& db_path,
    std::string required_registration_token) {
  sqlite3* db = nullptr;
  if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
    std::string error = db ? sqlite3_errmsg(db) : "sqlite3_open failed";
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return Result<std::unique_ptr<SqliteStore>>::Err(error);
  }

  auto store = std::unique_ptr<SqliteStore>(
      new SqliteStore(db, std::move(required_registration_token)));
  auto secret = RandomBytes(32);
  if (!secret.ok()) {
    return Result<std::unique_ptr<SqliteStore>>::Err(secret.error());
  }
  store->token_hmac_secret_ = secret.take_value();

  auto init = store->InitSchema();
  if (!init.ok()) {
    return Result<std::unique_ptr<SqliteStore>>::Err(init.error());
  }

  return Result<std::unique_ptr<SqliteStore>>::Ok(std::move(store));
}

uint64_t SqliteStore::NowUnix() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<std::vector<uint8_t>> SqliteStore::RandomBytes(size_t bytes) {
  std::vector<uint8_t> out(bytes);
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    return Result<std::vector<uint8_t>>::Err("RAND_bytes failed");
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

std::string SqliteStore::RandomHex(size_t bytes) {
  auto random = RandomBytes(bytes);
  if (!random.ok()) {
    return {};
  }
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : random.value()) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

Result<void> SqliteStore::CleanupAuthState(uint64_t now) {
  auto prune_challenges = Prepare(
      db_,
      "DELETE FROM auth_challenges WHERE used != 0 OR expires_at_unix < ?;");
  if (!prune_challenges.ok()) {
    return Result<void>::Err(prune_challenges.error());
  }
  auto prune_challenges_stmt = prune_challenges.take_value();
  if (sqlite3_bind_int64(prune_challenges_stmt.get(), 1,
                         static_cast<sqlite3_int64>(now)) != SQLITE_OK) {
    return Result<void>::Err("bind auth challenge cleanup failed");
  }
  auto prune_challenges_step = StepDone(db_, prune_challenges_stmt.get());
  if (!prune_challenges_step.ok()) {
    return prune_challenges_step;
  }

  auto prune_sessions = Prepare(
      db_,
      "DELETE FROM sessions WHERE expires_at_unix < ?;");
  if (!prune_sessions.ok()) {
    return Result<void>::Err(prune_sessions.error());
  }
  auto prune_sessions_stmt = prune_sessions.take_value();
  if (sqlite3_bind_int64(prune_sessions_stmt.get(), 1,
                         static_cast<sqlite3_int64>(now)) != SQLITE_OK) {
    return Result<void>::Err("bind session cleanup failed");
  }
  return StepDone(db_, prune_sessions_stmt.get());
}

Result<void> SqliteStore::EnforceRateLimit(
    std::unordered_map<std::string, std::deque<uint64_t>>* buckets,
    const std::string& user_id,
    uint64_t now,
    size_t max_attempts,
    uint64_t window_seconds,
    const char* error_text) {
  auto& bucket = (*buckets)[user_id];
  while (!bucket.empty() && bucket.front() + window_seconds <= now) {
    bucket.pop_front();
  }
  if (bucket.size() >= max_attempts) {
    return Result<void>::Err(error_text);
  }
  bucket.push_back(now);
  return Result<void>::Ok();
}

Result<std::vector<uint8_t>> SqliteStore::HashToken(
    const std::vector<uint8_t>& token) const {
  auto hash = crypto::HmacSha256(token_hmac_secret_, token);
  if (!hash.ok()) {
    return Result<std::vector<uint8_t>>::Err(hash.error());
  }
  return Result<std::vector<uint8_t>>::Ok(hash.take_value());
}

Result<void> SqliteStore::AppendAuthAudit(const std::string& user_id,
                                          const std::string& event,
                                          const std::string& detail) {
  auto stmt_result = Prepare(
      db_,
      "INSERT INTO auth_audit_log(event_time_unix, user_id, event, detail) VALUES(?, ?, ?, ?);");
  if (!stmt_result.ok()) {
    return Result<void>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();

  const uint64_t now = NowUnix();
  if (sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(now)) != SQLITE_OK) {
    return Result<void>::Err("bind auth audit timestamp failed");
  }
  auto bind_user = BindText(stmt.get(), 2, user_id);
  if (!bind_user.ok()) {
    return bind_user;
  }
  auto bind_event = BindText(stmt.get(), 3, event);
  if (!bind_event.ok()) {
    return bind_event;
  }
  auto bind_detail = BindText(stmt.get(), 4, detail);
  if (!bind_detail.ok()) {
    return bind_detail;
  }
  return StepDone(db_, stmt.get());
}

Result<void> SqliteStore::InitSchema() {
  constexpr const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS accounts (
  user_id TEXT PRIMARY KEY,
  transport_auth_public_key BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_challenges (
  challenge_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_nonce BLOB NOT NULL,
  server_nonce BLOB NOT NULL,
  expires_at_unix INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY,
  user_id TEXT NOT NULL,
  issued_at_unix INTEGER NOT NULL,
  expires_at_unix INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_time_unix INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bundles (
  user_id TEXT PRIMARY KEY,
  identity_sign_public_key BLOB NOT NULL,
  identity_mldsa_public_key BLOB NOT NULL,
  identity_dh_public_key BLOB NOT NULL,
  spk_ec_id INTEGER NOT NULL,
  spk_ec_public_key BLOB NOT NULL,
  spk_ec_sig_ed25519 BLOB NOT NULL,
  spk_ec_sig_mldsa65 BLOB NOT NULL,
  spk_pq_id INTEGER NOT NULL,
  spk_pq_public_key BLOB NOT NULL,
  spk_pq_sig_ed25519 BLOB NOT NULL,
  spk_pq_sig_mldsa65 BLOB NOT NULL,
  bundle_sig_ed25519 BLOB NOT NULL,
  bundle_sig_mldsa65 BLOB NOT NULL,
  version TEXT NOT NULL,
  cipher_suite TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_ec (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  key_id INTEGER NOT NULL,
  public_key BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_pq (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  key_id INTEGER NOT NULL,
  public_key BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS inbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  envelope BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_one_time_ec_user ON one_time_ec(user_id, rowid);
CREATE INDEX IF NOT EXISTS idx_one_time_pq_user ON one_time_pq(user_id, rowid);
CREATE INDEX IF NOT EXISTS idx_inbox_user ON inbox(user_id, id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at_unix);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry ON auth_challenges(expires_at_unix, used);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at_unix, revoked);
CREATE INDEX IF NOT EXISTS idx_auth_audit_event_time ON auth_audit_log(event_time_unix, id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_user ON auth_audit_log(user_id, event_time_unix);
)SQL";

  auto init = Exec(db_, kSchema);
  if (!init.ok()) {
    return init;
  }

  auto add_bundle_sig_ed = ExecAllowingDuplicateColumn(
      db_,
      "ALTER TABLE bundles ADD COLUMN bundle_sig_ed25519 BLOB NOT NULL DEFAULT X'';");
  if (!add_bundle_sig_ed.ok()) {
    return add_bundle_sig_ed;
  }
  auto add_bundle_sig_ml = ExecAllowingDuplicateColumn(
      db_,
      "ALTER TABLE bundles ADD COLUMN bundle_sig_mldsa65 BLOB NOT NULL DEFAULT X'';");
  if (!add_bundle_sig_ml.ok()) {
    return add_bundle_sig_ml;
  }

  return Result<void>::Ok();
}

Result<void> SqliteStore::RegisterTransportIdentity(
    const protocol::RegisterRequest& request) {
  std::scoped_lock lock(mu_);

  if (!IsValidUserId(request.user_id)) {
    AppendAuthAudit(request.user_id, "register_rejected", "invalid_user_id");
    return Result<void>::Err(
        "invalid user_id (allowed: lowercase a-z, 0-9, '-', '_', '.', max 64)");
  }
  if (request.transport_auth_public_key.empty() ||
      request.transport_auth_public_key.size() > kMaxTransportAuthPublicKeyBytes) {
    AppendAuthAudit(request.user_id, "register_rejected", "invalid_public_key_size");
    return Result<void>::Err("invalid transport auth public key size");
  }
  if (request.proof_signature_mldsa65.size() < kMinMlDsaSignatureBytes ||
      request.proof_signature_mldsa65.size() > kMaxMlDsaSignatureBytes) {
    AppendAuthAudit(request.user_id, "register_rejected", "invalid_registration_proof_size");
    return Result<void>::Err("invalid registration proof signature size");
  }
  if (request.rotation_signature_mldsa65.has_value() &&
      (request.rotation_signature_mldsa65->size() < kMinMlDsaSignatureBytes ||
       request.rotation_signature_mldsa65->size() > kMaxMlDsaSignatureBytes)) {
    AppendAuthAudit(request.user_id, "register_rejected", "invalid_rotation_signature_size");
    return Result<void>::Err("invalid rotation signature size");
  }

  auto register_sign_input = protocol::BuildTransportRegisterSignInput(
      request.user_id, request.transport_auth_public_key);
  auto register_sig_ok = crypto::MlDsa65::Verify(request.transport_auth_public_key,
                                                 register_sign_input,
                                                 request.proof_signature_mldsa65);
  if (!register_sig_ok.ok()) {
    AppendAuthAudit(request.user_id, "register_rejected", "registration_proof_invalid");
    return Result<void>::Err("transport identity registration proof invalid");
  }

  auto select_result = Prepare(
      db_, "SELECT transport_auth_public_key FROM accounts WHERE user_id = ?;");
  if (!select_result.ok()) {
    return Result<void>::Err(select_result.error());
  }
  auto select_stmt = select_result.take_value();
  auto bind_user = BindText(select_stmt.get(), 1, request.user_id);
  if (!bind_user.ok()) {
    return bind_user;
  }

  int rc = sqlite3_step(select_stmt.get());
  if (rc == SQLITE_ROW) {
    auto existing = ColumnBlob(select_stmt.get(), 0);
    if (existing != request.transport_auth_public_key) {
      bool rotated = false;
      if (request.rotation_signature_mldsa65.has_value()) {
        auto rotate_sign_input = protocol::BuildTransportRegisterRotateSignInput(
            request.user_id,
            existing,
            request.transport_auth_public_key);
        auto rotate_sig_ok = crypto::MlDsa65::Verify(existing,
                                                     rotate_sign_input,
                                                     *request.rotation_signature_mldsa65);
        rotated = rotate_sig_ok.ok();
      }

      bool recovered = false;
      if (!rotated && !required_registration_token_.empty()) {
        auto token_verify = VerifyProvisioningToken(required_registration_token_,
                                                    request.user_id,
                                                    request.registration_token);
        recovered = token_verify.ok();
      }

      if (!rotated && !recovered) {
        AppendAuthAudit(request.user_id, "register_rejected", "rotation_or_recovery_required");
        return Result<void>::Err(
            "transport identity already registered with different key (rotation/recovery required)");
      }

      auto begin = Begin(db_);
      if (!begin.ok()) {
        return Result<void>::Err(begin.error());
      }

      auto update_result = Prepare(
          db_,
          "UPDATE accounts SET transport_auth_public_key = ? WHERE user_id = ?;");
      if (!update_result.ok()) {
        Rollback(db_);
        return Result<void>::Err(update_result.error());
      }
      auto update_stmt = update_result.take_value();
      auto bind_new_key = BindBlob(update_stmt.get(), 1, request.transport_auth_public_key);
      if (!bind_new_key.ok()) {
        Rollback(db_);
        return bind_new_key;
      }
      auto bind_update_user = BindText(update_stmt.get(), 2, request.user_id);
      if (!bind_update_user.ok()) {
        Rollback(db_);
        return bind_update_user;
      }
      auto update_step = StepDone(db_, update_stmt.get());
      if (!update_step.ok()) {
        Rollback(db_);
        return update_step;
      }

      auto revoke_result =
          Prepare(db_, "UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0;");
      if (!revoke_result.ok()) {
        Rollback(db_);
        return Result<void>::Err(revoke_result.error());
      }
      auto revoke_stmt = revoke_result.take_value();
      auto bind_revoke_user = BindText(revoke_stmt.get(), 1, request.user_id);
      if (!bind_revoke_user.ok()) {
        Rollback(db_);
        return bind_revoke_user;
      }
      auto revoke_step = StepDone(db_, revoke_stmt.get());
      if (!revoke_step.ok()) {
        Rollback(db_);
        return revoke_step;
      }

      auto commit = Commit(db_);
      if (!commit.ok()) {
        Rollback(db_);
        return commit;
      }
      AppendAuthAudit(request.user_id,
                      "register_rotated",
                      rotated ? "rotation_signature" : "recovery_token");
      return Result<void>::Ok();
    }
    AppendAuthAudit(request.user_id, "register_ok", "already_registered");
    return Result<void>::Ok();
  }
  if (rc != SQLITE_DONE) {
    return Result<void>::Err(sqlite3_errmsg(db_));
  }

  if (!required_registration_token_.empty()) {
    auto token_verify = VerifyProvisioningToken(required_registration_token_,
                                                request.user_id,
                                                request.registration_token);
    if (!token_verify.ok()) {
      AppendAuthAudit(request.user_id, "register_rejected", "invalid_registration_token");
      return token_verify;
    }
  }

  auto insert_result = Prepare(
      db_,
      "INSERT INTO accounts(user_id, transport_auth_public_key) VALUES(?, ?);");
  if (!insert_result.ok()) {
    return Result<void>::Err(insert_result.error());
  }
  auto insert_stmt = insert_result.take_value();

  auto bind_insert_user = BindText(insert_stmt.get(), 1, request.user_id);
  if (!bind_insert_user.ok()) {
    return bind_insert_user;
  }
  auto bind_insert_key =
      BindBlob(insert_stmt.get(), 2, request.transport_auth_public_key);
  if (!bind_insert_key.ok()) {
    return bind_insert_key;
  }

  auto step = StepDone(db_, insert_stmt.get());
  if (!step.ok()) {
    return step;
  }
  AppendAuthAudit(request.user_id, "register_ok", "new_account");
  return Result<void>::Ok();
}

Result<protocol::AuthBeginResponse> SqliteStore::BeginTransportAuthentication(
    const protocol::AuthBeginRequest& request) {
  std::scoped_lock lock(mu_);
  const uint64_t now = NowUnix();

  auto cleanup = CleanupAuthState(now);
  if (!cleanup.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(cleanup.error());
  }
  if (!IsValidUserId(request.user_id)) {
    AppendAuthAudit(request.user_id, "auth_begin_rejected", "invalid_user_id");
    return Result<protocol::AuthBeginResponse>::Err("invalid user_id");
  }
  if (request.client_nonce.size() != kExpectedAuthNonceBytes) {
    AppendAuthAudit(request.user_id, "auth_begin_rejected", "invalid_client_nonce_size");
    return Result<protocol::AuthBeginResponse>::Err("invalid client nonce size");
  }
  auto rate_limit = EnforceRateLimit(&auth_begin_attempts_,
                                     request.user_id,
                                     now,
                                     kMaxAuthBeginAttemptsPerWindow,
                                     kAuthRateWindowSeconds,
                                     "auth begin rate limit exceeded");
  if (!rate_limit.ok()) {
    AppendAuthAudit(request.user_id, "auth_begin_rejected", "rate_limit");
    return Result<protocol::AuthBeginResponse>::Err(rate_limit.error());
  }

  auto account_result =
      Prepare(db_, "SELECT 1 FROM accounts WHERE user_id = ? LIMIT 1;");
  if (!account_result.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(account_result.error());
  }
  auto account_stmt = account_result.take_value();
  auto bind_user = BindText(account_stmt.get(), 1, request.user_id);
  if (!bind_user.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(bind_user.error());
  }
  if (sqlite3_step(account_stmt.get()) != SQLITE_ROW) {
    AppendAuthAudit(request.user_id, "auth_begin_rejected", "unknown_user");
    return Result<protocol::AuthBeginResponse>::Err("authentication failed");
  }

  protocol::AuthBeginResponse response;
  response.challenge_id = RandomHex(16);
  auto nonce = RandomBytes(32);
  if (!nonce.ok() || response.challenge_id.empty()) {
    return Result<protocol::AuthBeginResponse>::Err("RNG failed");
  }
  response.server_nonce = nonce.take_value();
  response.expires_at_unix = now + 60;

  auto insert_result = Prepare(
      db_,
      "INSERT INTO auth_challenges(challenge_id, user_id, client_nonce, server_nonce, "
      "expires_at_unix, used) VALUES(?, ?, ?, ?, ?, 0);");
  if (!insert_result.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(insert_result.error());
  }
  auto insert_stmt = insert_result.take_value();

  auto bind_id = BindText(insert_stmt.get(), 1, response.challenge_id);
  if (!bind_id.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(bind_id.error());
  }
  auto bind_req_user = BindText(insert_stmt.get(), 2, request.user_id);
  if (!bind_req_user.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(bind_req_user.error());
  }
  auto bind_client_nonce = BindBlob(insert_stmt.get(), 3, request.client_nonce);
  if (!bind_client_nonce.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(bind_client_nonce.error());
  }
  auto bind_server_nonce = BindBlob(insert_stmt.get(), 4, response.server_nonce);
  if (!bind_server_nonce.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(bind_server_nonce.error());
  }
  if (sqlite3_bind_int64(insert_stmt.get(), 5,
                         static_cast<sqlite3_int64>(response.expires_at_unix)) !=
      SQLITE_OK) {
    return Result<protocol::AuthBeginResponse>::Err(
        "bind auth challenge expiry failed");
  }

  auto step = StepDone(db_, insert_stmt.get());
  if (!step.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(step.error());
  }

  AppendAuthAudit(request.user_id, "auth_begin_ok", "challenge_issued");

  return Result<protocol::AuthBeginResponse>::Ok(std::move(response));
}

Result<protocol::AuthFinishResponse> SqliteStore::FinishTransportAuthentication(
    const protocol::AuthFinishRequest& request) {
  std::scoped_lock lock(mu_);
  const uint64_t now = NowUnix();

  auto cleanup = CleanupAuthState(now);
  if (!cleanup.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(cleanup.error());
  }
  if (!IsValidUserId(request.user_id)) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "invalid_user_id");
    return Result<protocol::AuthFinishResponse>::Err("invalid user_id");
  }
  if (!IsValidChallengeId(request.challenge_id)) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "invalid_challenge_id");
    return Result<protocol::AuthFinishResponse>::Err("invalid challenge id");
  }
  if (request.client_nonce.size() != kExpectedAuthNonceBytes ||
      request.server_nonce.size() != kExpectedAuthNonceBytes) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "invalid_nonce_size");
    return Result<protocol::AuthFinishResponse>::Err("invalid auth nonce size");
  }
  if (request.signature_mldsa65.size() < kMinMlDsaSignatureBytes ||
      request.signature_mldsa65.size() > kMaxMlDsaSignatureBytes) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "invalid_signature_size");
    return Result<protocol::AuthFinishResponse>::Err("invalid auth signature size");
  }
  auto rate_limit = EnforceRateLimit(&auth_finish_attempts_,
                                     request.user_id,
                                     now,
                                     kMaxAuthFinishAttemptsPerWindow,
                                     kAuthRateWindowSeconds,
                                     "auth finish rate limit exceeded");
  if (!rate_limit.ok()) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "rate_limit");
    return Result<protocol::AuthFinishResponse>::Err(rate_limit.error());
  }

  auto begin = Begin(db_);
  if (!begin.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(begin.error());
  }

  auto challenge_result = Prepare(
      db_,
      "SELECT user_id, client_nonce, server_nonce, expires_at_unix, used "
      "FROM auth_challenges WHERE challenge_id = ?;");
  if (!challenge_result.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(challenge_result.error());
  }
  auto challenge_stmt = challenge_result.take_value();
  auto bind_challenge = BindText(challenge_stmt.get(), 1, request.challenge_id);
  if (!bind_challenge.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(bind_challenge.error());
  }

  if (sqlite3_step(challenge_stmt.get()) != SQLITE_ROW) {
    Rollback(db_);
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "unknown_challenge");
    return Result<protocol::AuthFinishResponse>::Err("unknown challenge");
  }

  const unsigned char* db_user_text = sqlite3_column_text(challenge_stmt.get(), 0);
  std::string db_user = db_user_text ? reinterpret_cast<const char*>(db_user_text) : "";
  auto db_client_nonce = ColumnBlob(challenge_stmt.get(), 1);
  auto db_server_nonce = ColumnBlob(challenge_stmt.get(), 2);
  uint64_t db_expires =
      static_cast<uint64_t>(sqlite3_column_int64(challenge_stmt.get(), 3));
  bool db_used = sqlite3_column_int(challenge_stmt.get(), 4) != 0;

  if (db_used) {
    Rollback(db_);
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "challenge_used");
    return Result<protocol::AuthFinishResponse>::Err("challenge already used");
  }
  if (NowUnix() > db_expires) {
    Rollback(db_);
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "challenge_expired");
    return Result<protocol::AuthFinishResponse>::Err("challenge expired");
  }
  if (db_user != request.user_id || db_client_nonce != request.client_nonce ||
      db_server_nonce != request.server_nonce ||
      db_expires != request.expires_at_unix) {
    Rollback(db_);
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "challenge_mismatch");
    return Result<protocol::AuthFinishResponse>::Err("challenge mismatch");
  }

  auto mark_used_result = Prepare(
      db_, "UPDATE auth_challenges SET used = 1 WHERE challenge_id = ? AND used = 0;");
  if (!mark_used_result.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(mark_used_result.error());
  }
  auto mark_used_stmt = mark_used_result.take_value();
  auto bind_mark = BindText(mark_used_stmt.get(), 1, request.challenge_id);
  if (!bind_mark.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(bind_mark.error());
  }
  auto step_mark = StepDone(db_, mark_used_stmt.get());
  if (!step_mark.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(step_mark.error());
  }
  if (sqlite3_changes(db_) != 1) {
    Rollback(db_);
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "challenge_used");
    return Result<protocol::AuthFinishResponse>::Err("challenge already used");
  }

  auto commit = Commit(db_);
  if (!commit.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(commit.error());
  }

  auto account_result = Prepare(
      db_,
      "SELECT transport_auth_public_key FROM accounts WHERE user_id = ?;");
  if (!account_result.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(account_result.error());
  }
  auto account_stmt = account_result.take_value();
  auto bind_account = BindText(account_stmt.get(), 1, request.user_id);
  if (!bind_account.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(bind_account.error());
  }
  if (sqlite3_step(account_stmt.get()) != SQLITE_ROW) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "unknown_user");
    return Result<protocol::AuthFinishResponse>::Err("authentication failed");
  }
  auto transport_auth_pub = ColumnBlob(account_stmt.get(), 0);

  auto sign_input = protocol::BuildTransportAuthSignInput(
      request.user_id,
      request.client_nonce,
      request.server_nonce,
      request.challenge_id,
      request.expires_at_unix);
  auto verify = crypto::MlDsa65::Verify(transport_auth_pub,
                                        sign_input,
                                        request.signature_mldsa65);
  if (!verify.ok()) {
    AppendAuthAudit(request.user_id, "auth_finish_rejected", "signature_invalid");
    return Result<protocol::AuthFinishResponse>::Err("auth signature invalid");
  }

  protocol::AuthFinishResponse response;
  auto token = RandomBytes(32);
  if (!token.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(token.error());
  }
  response.session_token = token.take_value();
  response.expires_at_unix = now + 900;

  auto token_hash = HashToken(response.session_token);
  if (!token_hash.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(token_hash.error());
  }

  auto insert_session_result = Prepare(
      db_,
      "INSERT INTO sessions(token_hash, user_id, issued_at_unix, expires_at_unix, revoked) "
      "VALUES(?, ?, ?, ?, 0);");
  if (!insert_session_result.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(insert_session_result.error());
  }
  auto insert_session_stmt = insert_session_result.take_value();
  auto bind_token_hash = BindBlob(insert_session_stmt.get(), 1, token_hash.value());
  if (!bind_token_hash.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(bind_token_hash.error());
  }
  auto bind_session_user = BindText(insert_session_stmt.get(), 2, request.user_id);
  if (!bind_session_user.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(bind_session_user.error());
  }
  if (sqlite3_bind_int64(insert_session_stmt.get(), 3,
                         static_cast<sqlite3_int64>(now)) != SQLITE_OK ||
      sqlite3_bind_int64(insert_session_stmt.get(), 4,
                         static_cast<sqlite3_int64>(response.expires_at_unix)) !=
          SQLITE_OK) {
    return Result<protocol::AuthFinishResponse>::Err(
        "bind session timestamps failed");
  }
  auto step_session = StepDone(db_, insert_session_stmt.get());
  if (!step_session.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(step_session.error());
  }

  AppendAuthAudit(request.user_id, "auth_finish_ok", "session_issued");

  return Result<protocol::AuthFinishResponse>::Ok(std::move(response));
}

Result<std::string> SqliteStore::AuthenticateSessionToken(
    const std::vector<uint8_t>& session_token) {
  std::scoped_lock lock(mu_);
  const uint64_t now = NowUnix();

  auto cleanup = CleanupAuthState(now);
  if (!cleanup.ok()) {
    return Result<std::string>::Err(cleanup.error());
  }
  if (session_token.size() != kExpectedSessionTokenBytes) {
    AppendAuthAudit("unknown", "session_rejected", "invalid_token_size");
    return Result<std::string>::Err("invalid session token size");
  }

  auto token_hash = HashToken(session_token);
  if (!token_hash.ok()) {
    return Result<std::string>::Err(token_hash.error());
  }

  auto stmt_result = Prepare(
      db_,
      "SELECT user_id, expires_at_unix, revoked FROM sessions WHERE token_hash = ?;");
  if (!stmt_result.ok()) {
    return Result<std::string>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();
  auto bind_hash = BindBlob(stmt.get(), 1, token_hash.value());
  if (!bind_hash.ok()) {
    return Result<std::string>::Err(bind_hash.error());
  }

  if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
    AppendAuthAudit("unknown", "session_rejected", "invalid_session");
    return Result<std::string>::Err("invalid session");
  }

  const unsigned char* user_text = sqlite3_column_text(stmt.get(), 0);
  std::string user = user_text ? reinterpret_cast<const char*>(user_text) : "";
  uint64_t expires_at = static_cast<uint64_t>(sqlite3_column_int64(stmt.get(), 1));
  bool revoked = sqlite3_column_int(stmt.get(), 2) != 0;

  if (revoked) {
    AppendAuthAudit(user, "session_rejected", "revoked");
    return Result<std::string>::Err("session revoked");
  }
  if (now > expires_at) {
    AppendAuthAudit(user, "session_rejected", "expired");
    return Result<std::string>::Err("session expired");
  }

  AppendAuthAudit(user, "session_ok", "authenticated");
  return Result<std::string>::Ok(std::move(user));
}

Result<void> SqliteStore::RevokeSessionToken(
    const std::vector<uint8_t>& session_token) {
  std::scoped_lock lock(mu_);
  if (session_token.size() != kExpectedSessionTokenBytes) {
    AppendAuthAudit("unknown", "logout_rejected", "invalid_token_size");
    return Result<void>::Err("invalid session token size");
  }

  auto token_hash = HashToken(session_token);
  if (!token_hash.ok()) {
    return Result<void>::Err(token_hash.error());
  }

  auto select_result = Prepare(db_, "SELECT user_id FROM sessions WHERE token_hash = ?;");
  if (!select_result.ok()) {
    return Result<void>::Err(select_result.error());
  }
  auto select_stmt = select_result.take_value();
  auto bind_hash = BindBlob(select_stmt.get(), 1, token_hash.value());
  if (!bind_hash.ok()) {
    return bind_hash;
  }
  if (sqlite3_step(select_stmt.get()) != SQLITE_ROW) {
    AppendAuthAudit("unknown", "logout_rejected", "invalid_session");
    return Result<void>::Err("invalid session");
  }
  const unsigned char* user_text = sqlite3_column_text(select_stmt.get(), 0);
  const std::string user = user_text ? reinterpret_cast<const char*>(user_text) : "unknown";

  auto update_result =
      Prepare(db_, "UPDATE sessions SET revoked = 1 WHERE token_hash = ?;");
  if (!update_result.ok()) {
    return Result<void>::Err(update_result.error());
  }
  auto update_stmt = update_result.take_value();
  auto bind_update_hash = BindBlob(update_stmt.get(), 1, token_hash.value());
  if (!bind_update_hash.ok()) {
    return bind_update_hash;
  }
  auto step = StepDone(db_, update_stmt.get());
  if (!step.ok()) {
    return step;
  }
  if (sqlite3_changes(db_) != 1) {
    AppendAuthAudit(user, "logout_rejected", "invalid_session");
    return Result<void>::Err("invalid session");
  }
  AppendAuthAudit(user, "logout_ok", "session_revoked");
  return Result<void>::Ok();
}

Result<void> SqliteStore::PublishBundle(const protocol::PrekeyBundle& bundle) {
  std::scoped_lock lock(mu_);

  if (bundle.version != protocol::kProtocolVersion) {
    return Result<void>::Err("unsupported bundle version");
  }
  if (bundle.cipher_suite != protocol::kCipherSuite) {
    return Result<void>::Err("unsupported bundle cipher suite");
  }
  auto verify = protocol::VerifyPrekeyBundleSignatures(bundle);
  if (!verify.ok()) {
    return Result<void>::Err("invalid prekey bundle signatures: " + verify.error());
  }

  auto begin = Begin(db_);
  if (!begin.ok()) {
    return Result<void>::Err(begin.error());
  }

  auto stmt_result = Prepare(
      db_,
      "INSERT INTO bundles("
      "user_id, identity_sign_public_key, identity_mldsa_public_key, identity_dh_public_key,"
      "spk_ec_id, spk_ec_public_key, spk_ec_sig_ed25519, spk_ec_sig_mldsa65,"
      "spk_pq_id, spk_pq_public_key, spk_pq_sig_ed25519, spk_pq_sig_mldsa65,"
      "bundle_sig_ed25519, bundle_sig_mldsa65,"
      "version, cipher_suite"
      ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT(user_id) DO UPDATE SET "
      "identity_sign_public_key=excluded.identity_sign_public_key,"
      "identity_mldsa_public_key=excluded.identity_mldsa_public_key,"
      "identity_dh_public_key=excluded.identity_dh_public_key,"
      "spk_ec_id=excluded.spk_ec_id,"
      "spk_ec_public_key=excluded.spk_ec_public_key,"
      "spk_ec_sig_ed25519=excluded.spk_ec_sig_ed25519,"
      "spk_ec_sig_mldsa65=excluded.spk_ec_sig_mldsa65,"
      "spk_pq_id=excluded.spk_pq_id,"
      "spk_pq_public_key=excluded.spk_pq_public_key,"
      "spk_pq_sig_ed25519=excluded.spk_pq_sig_ed25519,"
      "spk_pq_sig_mldsa65=excluded.spk_pq_sig_mldsa65,"
      "bundle_sig_ed25519=excluded.bundle_sig_ed25519,"
      "bundle_sig_mldsa65=excluded.bundle_sig_mldsa65,"
      "version=excluded.version,"
      "cipher_suite=excluded.cipher_suite;");
  if (!stmt_result.ok()) {
    Rollback(db_);
    return Result<void>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();

  int idx = 1;
  auto bind_user = BindText(stmt.get(), idx++, bundle.user_id);
  if (!bind_user.ok()) {
    Rollback(db_);
    return bind_user;
  }
  auto bind_identity_sign = BindBlob(stmt.get(), idx++, bundle.identity_sign_public_key);
  if (!bind_identity_sign.ok()) {
    Rollback(db_);
    return bind_identity_sign;
  }
  auto bind_identity_mldsa = BindBlob(stmt.get(), idx++, bundle.identity_mldsa_public_key);
  if (!bind_identity_mldsa.ok()) {
    Rollback(db_);
    return bind_identity_mldsa;
  }
  auto bind_identity_dh = BindBlob(stmt.get(), idx++, bundle.identity_dh_public_key);
  if (!bind_identity_dh.ok()) {
    Rollback(db_);
    return bind_identity_dh;
  }
  auto bind_spk_ec_id = BindU32(stmt.get(), idx++, bundle.signed_prekey_ec.id);
  if (!bind_spk_ec_id.ok()) {
    Rollback(db_);
    return bind_spk_ec_id;
  }
  auto bind_spk_ec_pub = BindBlob(stmt.get(), idx++, bundle.signed_prekey_ec.public_key);
  if (!bind_spk_ec_pub.ok()) {
    Rollback(db_);
    return bind_spk_ec_pub;
  }
  auto bind_spk_ec_sig_ed =
      BindBlob(stmt.get(), idx++, bundle.signed_prekey_ec.signature_ed25519);
  if (!bind_spk_ec_sig_ed.ok()) {
    Rollback(db_);
    return bind_spk_ec_sig_ed;
  }
  auto bind_spk_ec_sig_ml =
      BindBlob(stmt.get(), idx++, bundle.signed_prekey_ec.signature_mldsa65);
  if (!bind_spk_ec_sig_ml.ok()) {
    Rollback(db_);
    return bind_spk_ec_sig_ml;
  }
  auto bind_spk_pq_id = BindU32(stmt.get(), idx++, bundle.signed_prekey_pq.id);
  if (!bind_spk_pq_id.ok()) {
    Rollback(db_);
    return bind_spk_pq_id;
  }
  auto bind_spk_pq_pub = BindBlob(stmt.get(), idx++, bundle.signed_prekey_pq.public_key);
  if (!bind_spk_pq_pub.ok()) {
    Rollback(db_);
    return bind_spk_pq_pub;
  }
  auto bind_spk_pq_sig_ed =
      BindBlob(stmt.get(), idx++, bundle.signed_prekey_pq.signature_ed25519);
  if (!bind_spk_pq_sig_ed.ok()) {
    Rollback(db_);
    return bind_spk_pq_sig_ed;
  }
  auto bind_spk_pq_sig_ml =
      BindBlob(stmt.get(), idx++, bundle.signed_prekey_pq.signature_mldsa65);
  if (!bind_spk_pq_sig_ml.ok()) {
    Rollback(db_);
    return bind_spk_pq_sig_ml;
  }
  auto bind_bundle_sig_ed =
      BindBlob(stmt.get(), idx++, bundle.bundle_signature_ed25519);
  if (!bind_bundle_sig_ed.ok()) {
    Rollback(db_);
    return bind_bundle_sig_ed;
  }
  auto bind_bundle_sig_ml =
      BindBlob(stmt.get(), idx++, bundle.bundle_signature_mldsa65);
  if (!bind_bundle_sig_ml.ok()) {
    Rollback(db_);
    return bind_bundle_sig_ml;
  }
  auto bind_version = BindText(stmt.get(), idx++, bundle.version);
  if (!bind_version.ok()) {
    Rollback(db_);
    return bind_version;
  }
  auto bind_suite = BindText(stmt.get(), idx++, bundle.cipher_suite);
  if (!bind_suite.ok()) {
    Rollback(db_);
    return bind_suite;
  }

  auto step_bundle = StepDone(db_, stmt.get());
  if (!step_bundle.ok()) {
    Rollback(db_);
    return step_bundle;
  }

  auto delete_ec = Prepare(db_, "DELETE FROM one_time_ec WHERE user_id = ?;");
  if (!delete_ec.ok()) {
    Rollback(db_);
    return Result<void>::Err(delete_ec.error());
  }
  auto delete_ec_stmt = delete_ec.take_value();
  auto bind_delete_ec = BindText(delete_ec_stmt.get(), 1, bundle.user_id);
  if (!bind_delete_ec.ok()) {
    Rollback(db_);
    return bind_delete_ec;
  }
  auto step_delete_ec = StepDone(db_, delete_ec_stmt.get());
  if (!step_delete_ec.ok()) {
    Rollback(db_);
    return step_delete_ec;
  }

  auto delete_pq = Prepare(db_, "DELETE FROM one_time_pq WHERE user_id = ?;");
  if (!delete_pq.ok()) {
    Rollback(db_);
    return Result<void>::Err(delete_pq.error());
  }
  auto delete_pq_stmt = delete_pq.take_value();
  auto bind_delete_pq = BindText(delete_pq_stmt.get(), 1, bundle.user_id);
  if (!bind_delete_pq.ok()) {
    Rollback(db_);
    return bind_delete_pq;
  }
  auto step_delete_pq = StepDone(db_, delete_pq_stmt.get());
  if (!step_delete_pq.ok()) {
    Rollback(db_);
    return step_delete_pq;
  }

  for (const auto& one_time_ec : bundle.one_time_ec) {
    auto insert = InsertOneTimeEc(db_, bundle.user_id, one_time_ec);
    if (!insert.ok()) {
      Rollback(db_);
      return insert;
    }
  }

  for (const auto& one_time_pq : bundle.one_time_pq) {
    auto insert = InsertOneTimePq(db_, bundle.user_id, one_time_pq);
    if (!insert.ok()) {
      Rollback(db_);
      return insert;
    }
  }

  auto commit = Commit(db_);
  if (!commit.ok()) {
    Rollback(db_);
    return commit;
  }

  return Result<void>::Ok();
}

Result<protocol::PrekeyBundle> SqliteStore::AcquireBundleForSession(
    const std::string& user_id) {
  std::scoped_lock lock(mu_);

  auto begin = Begin(db_);
  if (!begin.ok()) {
    return Result<protocol::PrekeyBundle>::Err(begin.error());
  }

  auto stmt_result = Prepare(
      db_,
      "SELECT identity_sign_public_key, identity_mldsa_public_key, identity_dh_public_key,"
      "spk_ec_id, spk_ec_public_key, spk_ec_sig_ed25519, spk_ec_sig_mldsa65,"
      "spk_pq_id, spk_pq_public_key, spk_pq_sig_ed25519, spk_pq_sig_mldsa65,"
      "bundle_sig_ed25519, bundle_sig_mldsa65,"
      "version, cipher_suite "
      "FROM bundles WHERE user_id = ?;");
  if (!stmt_result.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();

  auto bind_user = BindText(stmt.get(), 1, user_id);
  if (!bind_user.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(bind_user.error());
  }

  if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err("no prekey bundle for user");
  }

  protocol::PrekeyBundle bundle;
  bundle.user_id = user_id;
  bundle.identity_sign_public_key = ColumnBlob(stmt.get(), 0);
  bundle.identity_mldsa_public_key = ColumnBlob(stmt.get(), 1);
  bundle.identity_dh_public_key = ColumnBlob(stmt.get(), 2);
  bundle.signed_prekey_ec.id = static_cast<uint32_t>(sqlite3_column_int64(stmt.get(), 3));
  bundle.signed_prekey_ec.public_key = ColumnBlob(stmt.get(), 4);
  bundle.signed_prekey_ec.signature_ed25519 = ColumnBlob(stmt.get(), 5);
  bundle.signed_prekey_ec.signature_mldsa65 = ColumnBlob(stmt.get(), 6);
  bundle.signed_prekey_pq.id = static_cast<uint32_t>(sqlite3_column_int64(stmt.get(), 7));
  bundle.signed_prekey_pq.public_key = ColumnBlob(stmt.get(), 8);
  bundle.signed_prekey_pq.signature_ed25519 = ColumnBlob(stmt.get(), 9);
  bundle.signed_prekey_pq.signature_mldsa65 = ColumnBlob(stmt.get(), 10);
  bundle.bundle_signature_ed25519 = ColumnBlob(stmt.get(), 11);
  bundle.bundle_signature_mldsa65 = ColumnBlob(stmt.get(), 12);

  const unsigned char* version = sqlite3_column_text(stmt.get(), 13);
  const unsigned char* suite = sqlite3_column_text(stmt.get(), 14);
  bundle.version = version ? reinterpret_cast<const char*>(version) : "";
  bundle.cipher_suite = suite ? reinterpret_cast<const char*>(suite) : "";

  auto ec_stmt_result = Prepare(
      db_, "SELECT rowid, key_id, public_key FROM one_time_ec WHERE user_id = ? ORDER BY rowid LIMIT 1;");
  if (!ec_stmt_result.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(ec_stmt_result.error());
  }
  auto ec_stmt = ec_stmt_result.take_value();
  auto bind_ec_user = BindText(ec_stmt.get(), 1, user_id);
  if (!bind_ec_user.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(bind_ec_user.error());
  }

  bool has_ec = false;
  int64_t ec_rowid = 0;
  protocol::OneTimePrekeyEc selected_ec;
  int ec_rc = sqlite3_step(ec_stmt.get());
  if (ec_rc == SQLITE_ROW) {
    has_ec = true;
    ec_rowid = sqlite3_column_int64(ec_stmt.get(), 0);
    selected_ec.id = static_cast<uint32_t>(sqlite3_column_int64(ec_stmt.get(), 1));
    selected_ec.public_key = ColumnBlob(ec_stmt.get(), 2);
  } else if (ec_rc != SQLITE_DONE) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(sqlite3_errmsg(db_));
  }

  auto pq_stmt_result = Prepare(
      db_, "SELECT rowid, key_id, public_key FROM one_time_pq WHERE user_id = ? ORDER BY rowid LIMIT 1;");
  if (!pq_stmt_result.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(pq_stmt_result.error());
  }
  auto pq_stmt = pq_stmt_result.take_value();
  auto bind_pq_user = BindText(pq_stmt.get(), 1, user_id);
  if (!bind_pq_user.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(bind_pq_user.error());
  }

  bool has_pq = false;
  int64_t pq_rowid = 0;
  protocol::OneTimePrekeyPq selected_pq;
  int pq_rc = sqlite3_step(pq_stmt.get());
  if (pq_rc == SQLITE_ROW) {
    has_pq = true;
    pq_rowid = sqlite3_column_int64(pq_stmt.get(), 0);
    selected_pq.id = static_cast<uint32_t>(sqlite3_column_int64(pq_stmt.get(), 1));
    selected_pq.public_key = ColumnBlob(pq_stmt.get(), 2);
  } else if (pq_rc != SQLITE_DONE) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(sqlite3_errmsg(db_));
  }

  if (has_ec && has_pq) {
    bundle.one_time_ec.push_back(std::move(selected_ec));
    bundle.one_time_pq.push_back(std::move(selected_pq));

    auto delete_ec = Prepare(db_, "DELETE FROM one_time_ec WHERE rowid = ?;");
    if (!delete_ec.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(delete_ec.error());
    }
    auto delete_ec_stmt = delete_ec.take_value();
    if (sqlite3_bind_int64(delete_ec_stmt.get(), 1, static_cast<sqlite3_int64>(ec_rowid)) !=
        SQLITE_OK) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err("bind one-time ec row delete failed");
    }
    auto delete_ec_step = StepDone(db_, delete_ec_stmt.get());
    if (!delete_ec_step.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(delete_ec_step.error());
    }

    auto delete_pq = Prepare(db_, "DELETE FROM one_time_pq WHERE rowid = ?;");
    if (!delete_pq.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(delete_pq.error());
    }
    auto delete_pq_stmt = delete_pq.take_value();
    if (sqlite3_bind_int64(delete_pq_stmt.get(), 1, static_cast<sqlite3_int64>(pq_rowid)) !=
        SQLITE_OK) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err("bind one-time pq row delete failed");
    }
    auto delete_pq_step = StepDone(db_, delete_pq_stmt.get());
    if (!delete_pq_step.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(delete_pq_step.error());
    }
  }

  auto commit = Commit(db_);
  if (!commit.ok()) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(commit.error());
  }

  return Result<protocol::PrekeyBundle>::Ok(std::move(bundle));
}

Result<void> SqliteStore::EnqueueEnvelope(const std::string& user_id,
                                          protocol::Envelope envelope) {
  std::scoped_lock lock(mu_);

  auto serialized = protocol::SerializeEnvelope(envelope);
  if (!serialized.ok()) {
    return Result<void>::Err(serialized.error());
  }

  auto stmt_result =
      Prepare(db_, "INSERT INTO inbox(user_id, envelope) VALUES(?, ?);");
  if (!stmt_result.ok()) {
    return Result<void>::Err(stmt_result.error());
  }
  auto stmt = stmt_result.take_value();

  auto bind_user = BindText(stmt.get(), 1, user_id);
  if (!bind_user.ok()) {
    return bind_user;
  }
  auto bind_payload = BindBlob(stmt.get(), 2, serialized.value());
  if (!bind_payload.ok()) {
    return bind_payload;
  }

  return StepDone(db_, stmt.get());
}

Result<std::vector<protocol::InboxEnvelope>> SqliteStore::DrainInbox(
    const std::string& user_id,
    std::optional<uint64_t> ack_up_to_inbox_id) {
  std::scoped_lock lock(mu_);

  auto begin = Begin(db_);
  if (!begin.ok()) {
    return Result<std::vector<protocol::InboxEnvelope>>::Err(begin.error());
  }

  if (ack_up_to_inbox_id.has_value()) {
    auto ack_result = Prepare(db_, "DELETE FROM inbox WHERE user_id = ? AND id <= ?;");
    if (!ack_result.ok()) {
      Rollback(db_);
      return Result<std::vector<protocol::InboxEnvelope>>::Err(ack_result.error());
    }
    auto ack_stmt = ack_result.take_value();
    auto bind_ack_user = BindText(ack_stmt.get(), 1, user_id);
    if (!bind_ack_user.ok()) {
      Rollback(db_);
      return Result<std::vector<protocol::InboxEnvelope>>::Err(bind_ack_user.error());
    }
    if (sqlite3_bind_int64(ack_stmt.get(), 2,
                           static_cast<sqlite3_int64>(*ack_up_to_inbox_id)) !=
        SQLITE_OK) {
      Rollback(db_);
      return Result<std::vector<protocol::InboxEnvelope>>::Err(
          "bind inbox ack id failed");
    }
    auto ack_step = StepDone(db_, ack_stmt.get());
    if (!ack_step.ok()) {
      Rollback(db_);
      return Result<std::vector<protocol::InboxEnvelope>>::Err(ack_step.error());
    }
  }

  auto select_result =
      Prepare(db_, "SELECT id, envelope FROM inbox WHERE user_id = ? ORDER BY id LIMIT ?;");
  if (!select_result.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::InboxEnvelope>>::Err(select_result.error());
  }
  auto select_stmt = select_result.take_value();

  auto bind_user = BindText(select_stmt.get(), 1, user_id);
  if (!bind_user.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::InboxEnvelope>>::Err(bind_user.error());
  }
  if (sqlite3_bind_int64(select_stmt.get(), 2,
                         static_cast<sqlite3_int64>(kMaxDrainInboxBatchItems)) !=
      SQLITE_OK) {
    Rollback(db_);
    return Result<std::vector<protocol::InboxEnvelope>>::Err(
        "bind inbox drain limit failed");
  }

  std::vector<protocol::InboxEnvelope> out;
  size_t total_payload_bytes = 0;
  while (true) {
    int rc = sqlite3_step(select_stmt.get());
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      Rollback(db_);
      return Result<std::vector<protocol::InboxEnvelope>>::Err(sqlite3_errmsg(db_));
    }

    uint64_t inbox_id = static_cast<uint64_t>(sqlite3_column_int64(select_stmt.get(), 0));
    auto payload = ColumnBlob(select_stmt.get(), 1);
    size_t estimated_size = payload.size() + sizeof(uint64_t) + 8;
    if (!out.empty() && total_payload_bytes + estimated_size > kMaxDrainInboxBatchBytes) {
      break;
    }
    auto envelope = protocol::DeserializeEnvelope(payload);
    if (!envelope.ok()) {
      Rollback(db_);
      return Result<std::vector<protocol::InboxEnvelope>>::Err(envelope.error());
    }
    total_payload_bytes += estimated_size;
    out.push_back(protocol::InboxEnvelope{inbox_id, envelope.take_value()});
  }

  auto commit = Commit(db_);
  if (!commit.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::InboxEnvelope>>::Err(commit.error());
  }

  return Result<std::vector<protocol::InboxEnvelope>>::Ok(std::move(out));
}

}  // namespace pqchat::server
