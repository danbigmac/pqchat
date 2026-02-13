#include "pqchat/server/sqlite_store.h"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include <openssl/rand.h>

#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/protocol/serialization.h"
#include "pqchat/protocol/transport_auth.h"

namespace pqchat::server {
namespace {

using StmtPtr = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

Result<void> Exec(sqlite3* db, const char* sql) {
  char* errmsg = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
    std::string message = errmsg ? errmsg : "sqlite3_exec failed";
    sqlite3_free(errmsg);
    return Result<void>::Err(message);
  }
  return Result<void>::Ok();
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

SqliteStore::SqliteStore(sqlite3* db) : db_(db) {}

SqliteStore::~SqliteStore() {
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

Result<std::unique_ptr<SqliteStore>> SqliteStore::Open(const std::string& db_path) {
  sqlite3* db = nullptr;
  if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
    std::string error = db ? sqlite3_errmsg(db) : "sqlite3_open failed";
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return Result<std::unique_ptr<SqliteStore>>::Err(error);
  }

  auto store = std::unique_ptr<SqliteStore>(new SqliteStore(db));
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

Result<std::vector<uint8_t>> SqliteStore::HashToken(
    const std::vector<uint8_t>& token) const {
  auto hash = crypto::HmacSha256(token_hmac_secret_, token);
  if (!hash.ok()) {
    return Result<std::vector<uint8_t>>::Err(hash.error());
  }
  return Result<std::vector<uint8_t>>::Ok(hash.take_value());
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
)SQL";

  return Exec(db_, kSchema);
}

Result<void> SqliteStore::RegisterTransportIdentity(
    const protocol::RegisterRequest& request) {
  std::scoped_lock lock(mu_);

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
      return Result<void>::Err(
          "transport identity already registered with different key");
    }
    return Result<void>::Ok();
  }
  if (rc != SQLITE_DONE) {
    return Result<void>::Err(sqlite3_errmsg(db_));
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

  return StepDone(db_, insert_stmt.get());
}

Result<protocol::AuthBeginResponse> SqliteStore::BeginTransportAuthentication(
    const protocol::AuthBeginRequest& request) {
  std::scoped_lock lock(mu_);

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
    return Result<protocol::AuthBeginResponse>::Err("unknown user");
  }

  protocol::AuthBeginResponse response;
  response.challenge_id = RandomHex(16);
  auto nonce = RandomBytes(32);
  if (!nonce.ok() || response.challenge_id.empty()) {
    return Result<protocol::AuthBeginResponse>::Err("RNG failed");
  }
  response.server_nonce = nonce.take_value();
  response.expires_at_unix = NowUnix() + 60;

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

  return Result<protocol::AuthBeginResponse>::Ok(std::move(response));
}

Result<protocol::AuthFinishResponse> SqliteStore::FinishTransportAuthentication(
    const protocol::AuthFinishRequest& request) {
  std::scoped_lock lock(mu_);

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
    return Result<protocol::AuthFinishResponse>::Err("challenge already used");
  }
  if (NowUnix() > db_expires) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err("challenge expired");
  }
  if (db_user != request.user_id || db_client_nonce != request.client_nonce ||
      db_server_nonce != request.server_nonce ||
      db_expires != request.expires_at_unix) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err("challenge mismatch");
  }

  auto account_result = Prepare(
      db_,
      "SELECT transport_auth_public_key FROM accounts WHERE user_id = ?;");
  if (!account_result.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(account_result.error());
  }
  auto account_stmt = account_result.take_value();
  auto bind_account = BindText(account_stmt.get(), 1, request.user_id);
  if (!bind_account.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(bind_account.error());
  }
  if (sqlite3_step(account_stmt.get()) != SQLITE_ROW) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err("unknown user");
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
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err("auth signature invalid");
  }

  auto mark_used_result = Prepare(
      db_, "UPDATE auth_challenges SET used = 1 WHERE challenge_id = ?;");
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

  protocol::AuthFinishResponse response;
  auto token = RandomBytes(32);
  if (!token.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(token.error());
  }
  response.session_token = token.take_value();
  uint64_t now = NowUnix();
  response.expires_at_unix = now + 900;

  auto token_hash = HashToken(response.session_token);
  if (!token_hash.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(token_hash.error());
  }

  auto insert_session_result = Prepare(
      db_,
      "INSERT INTO sessions(token_hash, user_id, issued_at_unix, expires_at_unix, revoked) "
      "VALUES(?, ?, ?, ?, 0);");
  if (!insert_session_result.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(insert_session_result.error());
  }
  auto insert_session_stmt = insert_session_result.take_value();
  auto bind_token_hash = BindBlob(insert_session_stmt.get(), 1, token_hash.value());
  if (!bind_token_hash.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(bind_token_hash.error());
  }
  auto bind_session_user = BindText(insert_session_stmt.get(), 2, request.user_id);
  if (!bind_session_user.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(bind_session_user.error());
  }
  if (sqlite3_bind_int64(insert_session_stmt.get(), 3,
                         static_cast<sqlite3_int64>(now)) != SQLITE_OK ||
      sqlite3_bind_int64(insert_session_stmt.get(), 4,
                         static_cast<sqlite3_int64>(response.expires_at_unix)) !=
          SQLITE_OK) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(
        "bind session timestamps failed");
  }
  auto step_session = StepDone(db_, insert_session_stmt.get());
  if (!step_session.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(step_session.error());
  }

  auto commit = Commit(db_);
  if (!commit.ok()) {
    Rollback(db_);
    return Result<protocol::AuthFinishResponse>::Err(commit.error());
  }

  return Result<protocol::AuthFinishResponse>::Ok(std::move(response));
}

Result<std::string> SqliteStore::AuthenticateSessionToken(
    const std::vector<uint8_t>& session_token) {
  std::scoped_lock lock(mu_);

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
    return Result<std::string>::Err("invalid session");
  }

  const unsigned char* user_text = sqlite3_column_text(stmt.get(), 0);
  std::string user = user_text ? reinterpret_cast<const char*>(user_text) : "";
  uint64_t expires_at = static_cast<uint64_t>(sqlite3_column_int64(stmt.get(), 1));
  bool revoked = sqlite3_column_int(stmt.get(), 2) != 0;

  if (revoked) {
    return Result<std::string>::Err("session revoked");
  }
  if (NowUnix() > expires_at) {
    return Result<std::string>::Err("session expired");
  }

  return Result<std::string>::Ok(std::move(user));
}

Result<void> SqliteStore::PublishBundle(const protocol::PrekeyBundle& bundle) {
  std::scoped_lock lock(mu_);

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
      "version, cipher_suite"
      ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
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

  if (bundle.one_time_ec.has_value()) {
    auto insert = InsertOneTimeEc(db_, bundle.user_id, *bundle.one_time_ec);
    if (!insert.ok()) {
      Rollback(db_);
      return insert;
    }
  }

  if (bundle.one_time_pq.has_value()) {
    auto insert = InsertOneTimePq(db_, bundle.user_id, *bundle.one_time_pq);
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

  const unsigned char* version = sqlite3_column_text(stmt.get(), 11);
  const unsigned char* suite = sqlite3_column_text(stmt.get(), 12);
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

  int ec_rc = sqlite3_step(ec_stmt.get());
  if (ec_rc == SQLITE_ROW) {
    sqlite3_int64 rowid = sqlite3_column_int64(ec_stmt.get(), 0);
    protocol::OneTimePrekeyEc opk;
    opk.id = static_cast<uint32_t>(sqlite3_column_int64(ec_stmt.get(), 1));
    opk.public_key = ColumnBlob(ec_stmt.get(), 2);
    bundle.one_time_ec = opk;

    auto del_stmt_result = Prepare(db_, "DELETE FROM one_time_ec WHERE rowid = ?;");
    if (!del_stmt_result.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(del_stmt_result.error());
    }
    auto del_stmt = del_stmt_result.take_value();
    if (sqlite3_bind_int64(del_stmt.get(), 1, rowid) != SQLITE_OK) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err("delete one_time_ec bind failed");
    }
    auto step_del = StepDone(db_, del_stmt.get());
    if (!step_del.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(step_del.error());
    }
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

  int pq_rc = sqlite3_step(pq_stmt.get());
  if (pq_rc == SQLITE_ROW) {
    sqlite3_int64 rowid = sqlite3_column_int64(pq_stmt.get(), 0);
    protocol::OneTimePrekeyPq opk;
    opk.id = static_cast<uint32_t>(sqlite3_column_int64(pq_stmt.get(), 1));
    opk.public_key = ColumnBlob(pq_stmt.get(), 2);
    bundle.one_time_pq = opk;

    auto del_stmt_result = Prepare(db_, "DELETE FROM one_time_pq WHERE rowid = ?;");
    if (!del_stmt_result.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(del_stmt_result.error());
    }
    auto del_stmt = del_stmt_result.take_value();
    if (sqlite3_bind_int64(del_stmt.get(), 1, rowid) != SQLITE_OK) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err("delete one_time_pq bind failed");
    }
    auto step_del = StepDone(db_, del_stmt.get());
    if (!step_del.ok()) {
      Rollback(db_);
      return Result<protocol::PrekeyBundle>::Err(step_del.error());
    }
  } else if (pq_rc != SQLITE_DONE) {
    Rollback(db_);
    return Result<protocol::PrekeyBundle>::Err(sqlite3_errmsg(db_));
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

Result<std::vector<protocol::Envelope>> SqliteStore::DrainInbox(
    const std::string& user_id) {
  std::scoped_lock lock(mu_);

  auto begin = Begin(db_);
  if (!begin.ok()) {
    return Result<std::vector<protocol::Envelope>>::Err(begin.error());
  }

  auto select_result =
      Prepare(db_, "SELECT envelope FROM inbox WHERE user_id = ? ORDER BY id;");
  if (!select_result.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::Envelope>>::Err(select_result.error());
  }
  auto select_stmt = select_result.take_value();

  auto bind_user = BindText(select_stmt.get(), 1, user_id);
  if (!bind_user.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::Envelope>>::Err(bind_user.error());
  }

  std::vector<protocol::Envelope> out;
  while (true) {
    int rc = sqlite3_step(select_stmt.get());
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      Rollback(db_);
      return Result<std::vector<protocol::Envelope>>::Err(sqlite3_errmsg(db_));
    }

    auto payload = ColumnBlob(select_stmt.get(), 0);
    auto envelope = protocol::DeserializeEnvelope(payload);
    if (!envelope.ok()) {
      Rollback(db_);
      return Result<std::vector<protocol::Envelope>>::Err(envelope.error());
    }
    out.push_back(envelope.take_value());
  }

  auto delete_result = Prepare(db_, "DELETE FROM inbox WHERE user_id = ?;");
  if (!delete_result.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::Envelope>>::Err(delete_result.error());
  }
  auto delete_stmt = delete_result.take_value();

  auto bind_delete_user = BindText(delete_stmt.get(), 1, user_id);
  if (!bind_delete_user.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::Envelope>>::Err(bind_delete_user.error());
  }

  auto step_delete = StepDone(db_, delete_stmt.get());
  if (!step_delete.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::Envelope>>::Err(step_delete.error());
  }

  auto commit = Commit(db_);
  if (!commit.ok()) {
    Rollback(db_);
    return Result<std::vector<protocol::Envelope>>::Err(commit.error());
  }

  return Result<std::vector<protocol::Envelope>>::Ok(std::move(out));
}

}  // namespace pqchat::server
