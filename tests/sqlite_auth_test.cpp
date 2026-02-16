#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

#include "pqchat/client/client.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/protocol/transport_auth.h"
#include "pqchat/server/sqlite_store.h"

namespace {

bool AssertTrue(bool value, const std::string& label) {
  if (!value) {
    std::cerr << "FAIL: " << label << "\n";
    return false;
  }
  return true;
}

bool Contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

std::string HexEncode(const std::vector<uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::string DeriveRegistrationToken(const std::string& provisioning_secret,
                                    const std::string& user_id) {
  auto token = pqchat::crypto::HmacSha256(pqchat::crypto::ToBytes(provisioning_secret),
                                          pqchat::crypto::ToBytes(user_id));
  if (!token.ok()) {
    return {};
  }
  return HexEncode(token.value());
}

pqchat::Result<std::vector<uint8_t>> BuildRegisterProof(
    const std::string& user_id,
    const pqchat::crypto::MlDsa65KeyPair& keypair) {
  auto sign_input = pqchat::protocol::BuildTransportRegisterSignInput(
      user_id, keypair.public_key);
  return pqchat::crypto::MlDsa65::Sign(keypair.private_key.get(), sign_input);
}

pqchat::Result<std::vector<uint8_t>> BuildRotateProof(
    const std::string& user_id,
    const pqchat::crypto::MlDsa65KeyPair& existing_keypair,
    const std::vector<uint8_t>& new_public_key) {
  auto sign_input = pqchat::protocol::BuildTransportRegisterRotateSignInput(
      user_id,
      existing_keypair.public_key,
      new_public_key);
  return pqchat::crypto::MlDsa65::Sign(existing_keypair.private_key.get(), sign_input);
}

std::string MakeTempDbPath() {
  char path[] = "/tmp/pqchat_sqlite_auth_XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) {
    return {};
  }
  close(fd);
  return std::string(path);
}

std::string MakeTempStateDir() {
  char dir_template[] = "/tmp/pqchat_sqlite_auth_state_XXXXXX";
  char* dir = mkdtemp(dir_template);
  if (dir == nullptr) {
    return {};
  }
  return std::string(dir);
}

}  // namespace

int main() {
  using pqchat::crypto::MlDsa65;
  using pqchat::protocol::AuthBeginRequest;
  using pqchat::protocol::AuthFinishRequest;
  using pqchat::protocol::BuildTransportAuthSignInput;
  using pqchat::protocol::RegisterRequest;
  using pqchat::server::SqliteStore;

  bool ok = true;
  const std::string db_path = MakeTempDbPath();
  ok &= AssertTrue(!db_path.empty(), "mkstemp db path");
  if (!ok) {
    return 1;
  }
  const std::string state_dir = MakeTempStateDir();
  ok &= AssertTrue(!state_dir.empty(), "mkdtemp sqlite auth state dir");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  ok &= AssertTrue(setenv("PQCHAT_STATE_DIR", state_dir.c_str(), 1) == 0,
                   "setenv PQCHAT_STATE_DIR");
  ok &= AssertTrue(setenv("PQCHAT_STATE_PASSPHRASE", "sqlite-auth-test-passphrase", 1) == 0,
                   "setenv PQCHAT_STATE_PASSPHRASE");
  if (!ok) {
    unlink(db_path.c_str());
    std::filesystem::remove_all(state_dir);
    return 1;
  }

  auto store = SqliteStore::Open(db_path);
  ok &= AssertTrue(store.ok(), "open sqlite store");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  auto auth_key = MlDsa65::GenerateKeyPair();
  ok &= AssertTrue(auth_key.ok(), "auth keygen");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  RegisterRequest register_request;
  register_request.user_id = "sqlite-user";
  register_request.transport_auth_public_key = auth_key.value().public_key;
  auto register_proof = BuildRegisterProof(register_request.user_id, auth_key.value());
  ok &= AssertTrue(register_proof.ok(), "register proof");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  register_request.proof_signature_mldsa65 = register_proof.take_value();
  ok &= AssertTrue(store.value()->RegisterTransportIdentity(register_request).ok(),
                   "register sqlite-user");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  AuthBeginRequest pre_rotate_begin;
  pre_rotate_begin.user_id = register_request.user_id;
  pre_rotate_begin.client_nonce = std::vector<uint8_t>(32, 0x31);
  auto pre_rotate_begin_resp = store.value()->BeginTransportAuthentication(pre_rotate_begin);
  ok &= AssertTrue(pre_rotate_begin_resp.ok(), "auth begin before rotation");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto pre_rotate_sign_input = BuildTransportAuthSignInput(pre_rotate_begin.user_id,
                                                           pre_rotate_begin.client_nonce,
                                                           pre_rotate_begin_resp.value().server_nonce,
                                                           pre_rotate_begin_resp.value().challenge_id,
                                                           pre_rotate_begin_resp.value().expires_at_unix);
  auto pre_rotate_sig =
      MlDsa65::Sign(auth_key.value().private_key.get(), pre_rotate_sign_input);
  ok &= AssertTrue(pre_rotate_sig.ok(), "auth signature before rotation");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  AuthFinishRequest pre_rotate_finish;
  pre_rotate_finish.user_id = pre_rotate_begin.user_id;
  pre_rotate_finish.challenge_id = pre_rotate_begin_resp.value().challenge_id;
  pre_rotate_finish.client_nonce = pre_rotate_begin.client_nonce;
  pre_rotate_finish.server_nonce = pre_rotate_begin_resp.value().server_nonce;
  pre_rotate_finish.expires_at_unix = pre_rotate_begin_resp.value().expires_at_unix;
  pre_rotate_finish.signature_mldsa65 = pre_rotate_sig.take_value();
  auto pre_rotate_finish_resp = store.value()->FinishTransportAuthentication(pre_rotate_finish);
  ok &= AssertTrue(pre_rotate_finish_resp.ok(), "auth finish before rotation");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto pre_rotation_token = pre_rotate_finish_resp.value().session_token;
  ok &= AssertTrue(store.value()->AuthenticateSessionToken(pre_rotation_token).ok(),
                   "session valid before rotation");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  auto rotated_key = MlDsa65::GenerateKeyPair();
  ok &= AssertTrue(rotated_key.ok(), "rotated auth keygen");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  RegisterRequest rotate_without_authorization;
  rotate_without_authorization.user_id = register_request.user_id;
  rotate_without_authorization.transport_auth_public_key = rotated_key.value().public_key;
  auto rotate_without_auth_proof = BuildRegisterProof(rotate_without_authorization.user_id,
                                                      rotated_key.value());
  ok &= AssertTrue(rotate_without_auth_proof.ok(), "rotate-without-auth register proof");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  rotate_without_authorization.proof_signature_mldsa65 =
      rotate_without_auth_proof.take_value();
  auto rotate_without_auth_result =
      store.value()->RegisterTransportIdentity(rotate_without_authorization);
  ok &= AssertTrue(!rotate_without_auth_result.ok() &&
                       Contains(rotate_without_auth_result.error(), "rotation/recovery"),
                   "rotation without authorization is rejected");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  RegisterRequest rotate_with_signature = rotate_without_authorization;
  auto rotate_signature = BuildRotateProof(rotate_with_signature.user_id,
                                           auth_key.value(),
                                           rotate_with_signature.transport_auth_public_key);
  ok &= AssertTrue(rotate_signature.ok(), "build rotation signature");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  rotate_with_signature.rotation_signature_mldsa65 = rotate_signature.take_value();
  ok &= AssertTrue(store.value()->RegisterTransportIdentity(rotate_with_signature).ok(),
                   "rotation with existing key signature succeeds");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto pre_rotation_after_rotate =
      store.value()->AuthenticateSessionToken(pre_rotation_token);
  ok &= AssertTrue(!pre_rotation_after_rotate.ok() &&
                       Contains(pre_rotation_after_rotate.error(), "revoked"),
                   "rotation revokes previously issued sessions");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto active_auth_key = rotated_key.take_value();

  AuthBeginRequest unknown_begin;
  unknown_begin.user_id = "sqlite-missing-user";
  unknown_begin.client_nonce = std::vector<uint8_t>(32, 0x01);
  auto unknown_begin_resp = store.value()->BeginTransportAuthentication(unknown_begin);
  ok &= AssertTrue(!unknown_begin_resp.ok() &&
                       Contains(unknown_begin_resp.error(), "authentication failed") &&
                       !Contains(unknown_begin_resp.error(), "unknown user"),
                   "auth begin masks unknown user");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  const std::string recovery_db_path = MakeTempDbPath();
  ok &= AssertTrue(!recovery_db_path.empty(), "mkstemp recovery db path");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  const std::string provisioning_secret = "sqlite-recovery-secret";
  auto recovery_store = SqliteStore::Open(recovery_db_path, provisioning_secret);
  ok &= AssertTrue(recovery_store.ok(), "open recovery sqlite store");
  if (!ok) {
    unlink(db_path.c_str());
    unlink(recovery_db_path.c_str());
    return 1;
  }
  RegisterRequest recovery_initial;
  recovery_initial.user_id = "recover-user";
  recovery_initial.transport_auth_public_key = auth_key.value().public_key;
  recovery_initial.registration_token =
      DeriveRegistrationToken(provisioning_secret, recovery_initial.user_id);
  auto recovery_initial_proof = BuildRegisterProof(recovery_initial.user_id, auth_key.value());
  ok &= AssertTrue(recovery_initial_proof.ok(), "build recovery initial proof");
  if (!ok) {
    unlink(db_path.c_str());
    unlink(recovery_db_path.c_str());
    return 1;
  }
  recovery_initial.proof_signature_mldsa65 = recovery_initial_proof.take_value();
  ok &= AssertTrue(recovery_store.value()->RegisterTransportIdentity(recovery_initial).ok(),
                   "register recovery initial identity");
  if (!ok) {
    unlink(db_path.c_str());
    unlink(recovery_db_path.c_str());
    return 1;
  }

  auto recovery_new_key = MlDsa65::GenerateKeyPair();
  ok &= AssertTrue(recovery_new_key.ok(), "recovery new keygen");
  if (!ok) {
    unlink(db_path.c_str());
    unlink(recovery_db_path.c_str());
    return 1;
  }
  RegisterRequest recovery_rotate;
  recovery_rotate.user_id = recovery_initial.user_id;
  recovery_rotate.transport_auth_public_key = recovery_new_key.value().public_key;
  recovery_rotate.registration_token =
      DeriveRegistrationToken(provisioning_secret, recovery_rotate.user_id);
  auto recovery_rotate_proof =
      BuildRegisterProof(recovery_rotate.user_id, recovery_new_key.value());
  ok &= AssertTrue(recovery_rotate_proof.ok(), "build recovery rotate proof");
  if (!ok) {
    unlink(db_path.c_str());
    unlink(recovery_db_path.c_str());
    return 1;
  }
  recovery_rotate.proof_signature_mldsa65 = recovery_rotate_proof.take_value();
  ok &= AssertTrue(recovery_store.value()->RegisterTransportIdentity(recovery_rotate).ok(),
                   "recovery token allows key replacement");
  unlink(recovery_db_path.c_str());

  AuthBeginRequest begin_request;
  begin_request.user_id = register_request.user_id;
  begin_request.client_nonce = std::vector<uint8_t>(32, 0x42);
  auto begin_response = store.value()->BeginTransportAuthentication(begin_request);
  ok &= AssertTrue(begin_response.ok(), "auth begin");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  AuthFinishRequest finish_bad;
  finish_bad.user_id = begin_request.user_id;
  finish_bad.challenge_id = begin_response.value().challenge_id;
  finish_bad.client_nonce = begin_request.client_nonce;
  finish_bad.server_nonce = begin_response.value().server_nonce;
  finish_bad.expires_at_unix = begin_response.value().expires_at_unix;
  finish_bad.signature_mldsa65 = std::vector<uint8_t>(128, 0xAA);
  auto bad_finish = store.value()->FinishTransportAuthentication(finish_bad);
  ok &= AssertTrue(!bad_finish.ok() &&
                       Contains(bad_finish.error(), "auth signature invalid"),
                   "first bad auth finish fails");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  auto sign_input = BuildTransportAuthSignInput(begin_request.user_id,
                                                begin_request.client_nonce,
                                                begin_response.value().server_nonce,
                                                begin_response.value().challenge_id,
                                                begin_response.value().expires_at_unix);
  auto signature = MlDsa65::Sign(active_auth_key.private_key.get(), sign_input);
  ok &= AssertTrue(signature.ok(), "generate valid signature");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  AuthFinishRequest finish_retry = finish_bad;
  finish_retry.signature_mldsa65 = signature.take_value();
  auto retry_finish = store.value()->FinishTransportAuthentication(finish_retry);
  ok &= AssertTrue(!retry_finish.ok() &&
                       Contains(retry_finish.error(), "challenge"),
                   "challenge is consumed after first auth finish attempt");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  RegisterRequest begin_limit_register;
  begin_limit_register.user_id = "sqlite-begin-limit";
  begin_limit_register.transport_auth_public_key = auth_key.value().public_key;
  auto begin_limit_proof = BuildRegisterProof(begin_limit_register.user_id, auth_key.value());
  ok &= AssertTrue(begin_limit_proof.ok(), "register begin-limit proof");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  begin_limit_register.proof_signature_mldsa65 = begin_limit_proof.take_value();
  ok &= AssertTrue(store.value()->RegisterTransportIdentity(begin_limit_register).ok(),
                   "register begin-limit user");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  for (int i = 0; i < 30; ++i) {
    AuthBeginRequest req;
    req.user_id = begin_limit_register.user_id;
    req.client_nonce = std::vector<uint8_t>(32, static_cast<uint8_t>(i));
    ok &= AssertTrue(store.value()->BeginTransportAuthentication(req).ok(),
                     "begin below rate limit");
    if (!ok) {
      unlink(db_path.c_str());
      return 1;
    }
  }
  AuthBeginRequest req_last;
  req_last.user_id = begin_limit_register.user_id;
  req_last.client_nonce = std::vector<uint8_t>(32, 0xEE);
  auto begin_limited = store.value()->BeginTransportAuthentication(req_last);
  ok &= AssertTrue(!begin_limited.ok() &&
                       Contains(begin_limited.error(), "rate limit"),
                   "begin rate limit enforced");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }

  RegisterRequest finish_limit_register;
  finish_limit_register.user_id = "sqlite-finish-limit";
  finish_limit_register.transport_auth_public_key = auth_key.value().public_key;
  auto finish_limit_proof =
      BuildRegisterProof(finish_limit_register.user_id, auth_key.value());
  ok &= AssertTrue(finish_limit_proof.ok(), "register finish-limit proof");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  finish_limit_register.proof_signature_mldsa65 = finish_limit_proof.take_value();
  ok &= AssertTrue(store.value()->RegisterTransportIdentity(finish_limit_register).ok(),
                   "register finish-limit user");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  for (int i = 0; i < 30; ++i) {
    AuthFinishRequest req;
    req.user_id = finish_limit_register.user_id;
    req.challenge_id = std::string(30, 'd') +
                       (i % 2 == 0 ? "0d" : "0e");
    req.client_nonce = std::vector<uint8_t>(32, 0x10);
    req.server_nonce = std::vector<uint8_t>(32, 0x20);
    req.expires_at_unix = 1;
    req.signature_mldsa65 = std::vector<uint8_t>(128, 0x30);
    auto finish = store.value()->FinishTransportAuthentication(req);
    ok &= AssertTrue(!finish.ok(), "finish attempt fails before rate limit");
    if (!ok) {
      unlink(db_path.c_str());
      return 1;
    }
  }
  AuthFinishRequest finish_last;
  finish_last.user_id = finish_limit_register.user_id;
  finish_last.challenge_id = std::string(32, 'f');
  finish_last.client_nonce = std::vector<uint8_t>(32, 0x10);
  finish_last.server_nonce = std::vector<uint8_t>(32, 0x20);
  finish_last.expires_at_unix = 1;
  finish_last.signature_mldsa65 = std::vector<uint8_t>(128, 0x30);
  auto finish_limited = store.value()->FinishTransportAuthentication(finish_last);
  ok &= AssertTrue(!finish_limited.ok() &&
                       Contains(finish_limited.error(), "rate limit"),
                   "finish rate limit enforced");

  AuthBeginRequest revoke_begin;
  revoke_begin.user_id = register_request.user_id;
  revoke_begin.client_nonce = std::vector<uint8_t>(32, 0x55);
  auto revoke_begin_resp = store.value()->BeginTransportAuthentication(revoke_begin);
  ok &= AssertTrue(revoke_begin_resp.ok(), "auth begin for revoke test");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto revoke_sign_input = BuildTransportAuthSignInput(
      revoke_begin.user_id,
      revoke_begin.client_nonce,
      revoke_begin_resp.value().server_nonce,
      revoke_begin_resp.value().challenge_id,
      revoke_begin_resp.value().expires_at_unix);
  auto revoke_sig = MlDsa65::Sign(active_auth_key.private_key.get(), revoke_sign_input);
  ok &= AssertTrue(revoke_sig.ok(), "auth signature for revoke test");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  AuthFinishRequest revoke_finish;
  revoke_finish.user_id = revoke_begin.user_id;
  revoke_finish.challenge_id = revoke_begin_resp.value().challenge_id;
  revoke_finish.client_nonce = revoke_begin.client_nonce;
  revoke_finish.server_nonce = revoke_begin_resp.value().server_nonce;
  revoke_finish.expires_at_unix = revoke_begin_resp.value().expires_at_unix;
  revoke_finish.signature_mldsa65 = revoke_sig.take_value();
  auto revoke_finish_resp = store.value()->FinishTransportAuthentication(revoke_finish);
  ok &= AssertTrue(revoke_finish_resp.ok(), "auth finish for revoke test");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto revoke_status = store.value()->RevokeSessionToken(revoke_finish_resp.value().session_token);
  ok &= AssertTrue(revoke_status.ok(), "revoke session token");
  auto revoked_auth =
      store.value()->AuthenticateSessionToken(revoke_finish_resp.value().session_token);
  ok &= AssertTrue(!revoked_auth.ok() && Contains(revoked_auth.error(), "revoked"),
                   "revoked session token rejected");

  sqlite3* raw = nullptr;
  ok &= AssertTrue(sqlite3_open(db_path.c_str(), &raw) == SQLITE_OK, "open sqlite for audit check");
  if (!ok) {
    if (raw != nullptr) {
      sqlite3_close(raw);
    }
    unlink(db_path.c_str());
    return 1;
  }
  sqlite3_stmt* stmt = nullptr;
  ok &= AssertTrue(sqlite3_prepare_v2(raw, "SELECT COUNT(*) FROM auth_audit_log;", -1, &stmt, nullptr) ==
                       SQLITE_OK,
                   "prepare auth audit count");
  if (!ok) {
    if (stmt != nullptr) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close(raw);
    unlink(db_path.c_str());
    return 1;
  }
  int count = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    count = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  sqlite3_close(raw);
  ok &= AssertTrue(count > 0, "auth audit log is persisted");

  auto publisher_result = pqchat::client::Client::Create("sqlite-opk-publisher");
  ok &= AssertTrue(publisher_result.ok(), "create sqlite OPK publisher client");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto publisher = publisher_result.take_value();
  ok &= AssertTrue(publisher.PublishPrekeys(store.value().get()).ok(),
                   "publish sqlite OPK publisher bundle");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto first_bundle = store.value()->AcquireBundleForSession("sqlite-opk-publisher");
  ok &= AssertTrue(first_bundle.ok() &&
                       first_bundle.value().one_time_ec.size() == 1 &&
                       first_bundle.value().one_time_pq.size() == 1,
                   "first acquire reserves exactly one EC and one PQ OPK");
  if (!ok) {
    unlink(db_path.c_str());
    return 1;
  }
  auto second_bundle = store.value()->AcquireBundleForSession("sqlite-opk-publisher");
  ok &= AssertTrue(second_bundle.ok() &&
                       second_bundle.value().one_time_ec.size() == 1 &&
                       second_bundle.value().one_time_pq.size() == 1 &&
                       second_bundle.value().one_time_ec.front().id !=
                           first_bundle.value().one_time_ec.front().id &&
                       second_bundle.value().one_time_pq.front().id !=
                           first_bundle.value().one_time_pq.front().id,
                   "second acquire reserves a different OPK pair");

  unlink(db_path.c_str());
  unsetenv("PQCHAT_STATE_DIR");
  unsetenv("PQCHAT_STATE_PASSPHRASE");
  std::filesystem::remove_all(state_dir);
  if (!ok) {
    return 1;
  }
  std::cout << "PASS: sqlite auth test suite\n";
  return 0;
}
