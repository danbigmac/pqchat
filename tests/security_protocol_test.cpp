#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "pqchat/client/client.h"
#include "pqchat/crypto/ed25519.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/crypto/mlkem.h"
#include "pqchat/crypto/x25519.h"
#include "pqchat/protocol/prekey_bundle.h"
#include "pqchat/protocol/transport_auth.h"
#include "pqchat/server/in_memory_server.h"

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

pqchat::Result<pqchat::protocol::PrekeyBundle> BuildBundleWithoutOneTimePrekeys(
    const std::string& user_id) {
  using pqchat::crypto::Ed25519;
  using pqchat::crypto::MlDsa65;
  using pqchat::crypto::MlKem768;
  using pqchat::crypto::X25519;
  using pqchat::protocol::BuildBundleSignInput;
  using pqchat::protocol::BuildEcPrekeySignInput;
  using pqchat::protocol::BuildPqPrekeySignInput;
  using pqchat::protocol::PrekeyBundle;
  using pqchat::protocol::kCipherSuite;
  using pqchat::protocol::kProtocolVersion;

  auto id_sign = Ed25519::GenerateKeyPair();
  if (!id_sign.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(id_sign.error());
  }
  auto id_mldsa = MlDsa65::GenerateKeyPair();
  if (!id_mldsa.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(id_mldsa.error());
  }
  auto id_dh = X25519::GenerateKeyPair();
  if (!id_dh.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(id_dh.error());
  }
  auto spk_ec = X25519::GenerateKeyPair();
  if (!spk_ec.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(spk_ec.error());
  }
  auto spk_pq = MlKem768::GenerateKeyPair();
  if (!spk_pq.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(spk_pq.error());
  }

  PrekeyBundle bundle;
  bundle.user_id = user_id;
  bundle.identity_sign_public_key = id_sign.value().public_key;
  bundle.identity_mldsa_public_key = id_mldsa.value().public_key;
  bundle.identity_dh_public_key = id_dh.value().public_key;
  bundle.version = kProtocolVersion;
  bundle.cipher_suite = kCipherSuite;

  bundle.signed_prekey_ec.id = 7;
  bundle.signed_prekey_ec.public_key = spk_ec.value().public_key;
  auto spk_ec_sig_input =
      BuildEcPrekeySignInput(bundle.signed_prekey_ec.id, bundle.signed_prekey_ec.public_key);
  auto spk_ec_sig_ed = Ed25519::Sign(id_sign.value().private_key, spk_ec_sig_input);
  if (!spk_ec_sig_ed.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(spk_ec_sig_ed.error());
  }
  auto spk_ec_sig_ml =
      MlDsa65::Sign(id_mldsa.value().private_key.get(), spk_ec_sig_input);
  if (!spk_ec_sig_ml.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(spk_ec_sig_ml.error());
  }
  bundle.signed_prekey_ec.signature_ed25519 = spk_ec_sig_ed.take_value();
  bundle.signed_prekey_ec.signature_mldsa65 = spk_ec_sig_ml.take_value();

  bundle.signed_prekey_pq.id = 9;
  bundle.signed_prekey_pq.public_key = spk_pq.value().public_key;
  auto spk_pq_sig_input =
      BuildPqPrekeySignInput(bundle.signed_prekey_pq.id, bundle.signed_prekey_pq.public_key);
  auto spk_pq_sig_ed = Ed25519::Sign(id_sign.value().private_key, spk_pq_sig_input);
  if (!spk_pq_sig_ed.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(spk_pq_sig_ed.error());
  }
  auto spk_pq_sig_ml =
      MlDsa65::Sign(id_mldsa.value().private_key.get(), spk_pq_sig_input);
  if (!spk_pq_sig_ml.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(spk_pq_sig_ml.error());
  }
  bundle.signed_prekey_pq.signature_ed25519 = spk_pq_sig_ed.take_value();
  bundle.signed_prekey_pq.signature_mldsa65 = spk_pq_sig_ml.take_value();

  auto bundle_sign_input = BuildBundleSignInput(bundle);
  auto bundle_sig_ed = Ed25519::Sign(id_sign.value().private_key, bundle_sign_input);
  if (!bundle_sig_ed.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(bundle_sig_ed.error());
  }
  auto bundle_sig_ml =
      MlDsa65::Sign(id_mldsa.value().private_key.get(), bundle_sign_input);
  if (!bundle_sig_ml.ok()) {
    return pqchat::Result<PrekeyBundle>::Err(bundle_sig_ml.error());
  }
  bundle.bundle_signature_ed25519 = bundle_sig_ed.take_value();
  bundle.bundle_signature_mldsa65 = bundle_sig_ml.take_value();
  return pqchat::Result<PrekeyBundle>::Ok(std::move(bundle));
}

class FixedBundleServer : public pqchat::server::IServerApi {
 public:
  explicit FixedBundleServer(pqchat::protocol::PrekeyBundle bundle)
      : bundle_(std::move(bundle)) {}

  pqchat::Result<void> RegisterTransportIdentity(
      const pqchat::protocol::RegisterRequest&) override {
    return pqchat::Result<void>::Err("not supported");
  }

  pqchat::Result<pqchat::protocol::AuthBeginResponse> BeginTransportAuthentication(
      const pqchat::protocol::AuthBeginRequest&) override {
    return pqchat::Result<pqchat::protocol::AuthBeginResponse>::Err("not supported");
  }

  pqchat::Result<pqchat::protocol::AuthFinishResponse> FinishTransportAuthentication(
      const pqchat::protocol::AuthFinishRequest&) override {
    return pqchat::Result<pqchat::protocol::AuthFinishResponse>::Err("not supported");
  }

  pqchat::Result<std::string> AuthenticateSessionToken(
      const std::vector<uint8_t>&) override {
    return pqchat::Result<std::string>::Err("not supported");
  }

  pqchat::Result<void> RevokeSessionToken(
      const std::vector<uint8_t>&) override {
    return pqchat::Result<void>::Err("not supported");
  }

  pqchat::Result<void> PublishBundle(
      const pqchat::protocol::PrekeyBundle&) override {
    return pqchat::Result<void>::Err("not supported");
  }

  pqchat::Result<pqchat::protocol::PrekeyBundle> AcquireBundleForSession(
      const std::string&) override {
    return pqchat::Result<pqchat::protocol::PrekeyBundle>::Ok(bundle_);
  }

  pqchat::Result<void> EnqueueEnvelope(const std::string&,
                                       pqchat::protocol::Envelope) override {
    return pqchat::Result<void>::Ok();
  }

  pqchat::Result<std::vector<pqchat::protocol::InboxEnvelope>> DrainInbox(
      const std::string&,
      std::optional<uint64_t>) override {
    return pqchat::Result<std::vector<pqchat::protocol::InboxEnvelope>>::Ok({});
  }

 private:
  pqchat::protocol::PrekeyBundle bundle_;
};

bool TestOpkRequirementOnInitiator() {
  using pqchat::client::Client;

  auto alice = Client::Create("alice-opk");
  if (!alice.ok()) {
    return AssertTrue(false, "alice create");
  }
  auto bundle = BuildBundleWithoutOneTimePrekeys("bob-opk");
  if (!bundle.ok()) {
    return AssertTrue(false, "build signed bundle without OPKs");
  }

  FixedBundleServer server(bundle.take_value());
  auto init_unverified = alice.value().InitiateSession(&server, "bob-opk", "hello");
  if (!AssertTrue(!init_unverified.ok(), "initiator requires peer verification first")) {
    return false;
  }
  auto safety = alice.value().GetPeerSafetyNumber("bob-opk");
  if (!AssertTrue(safety.ok(), "read bob safety number for OPK requirement test")) {
    return false;
  }
  auto verify = alice.value().VerifyPeerSafetyNumber("bob-opk", safety.value());
  if (!AssertTrue(verify.ok(), "verify bob safety number for OPK requirement test")) {
    return false;
  }
  auto init = alice.value().InitiateSession(&server, "bob-opk", "hello");
  return AssertTrue(!init.ok() && Contains(init.error(), "one-time prekeys"),
                    "initiator refuses handshake without one-time prekeys");
}

bool TestAcquireBundleReservesOneTimePrekeys() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  const std::string publisher_user = "reserve-publisher";
  auto publisher_result = Client::Create(publisher_user);
  if (!AssertTrue(publisher_result.ok(), "create reserve prekey publisher")) {
    return false;
  }
  auto publisher = publisher_result.take_value();
  if (!AssertTrue(publisher.PublishPrekeys(&server).ok(), "publish reserve prekeys")) {
    return false;
  }

  std::unordered_set<uint32_t> used_ec_ids;
  std::unordered_set<uint32_t> used_pq_ids;
  size_t reserved_count = 0;
  for (int i = 0; i < 64; ++i) {
    auto bundle = server.AcquireBundleForSession(publisher_user);
    if (!AssertTrue(bundle.ok(), "acquire bundle for one-time prekey reservation")) {
      return false;
    }
    if (bundle.value().one_time_ec.empty() || bundle.value().one_time_pq.empty()) {
      break;
    }
    if (!AssertTrue(bundle.value().one_time_ec.size() == 1 &&
                        bundle.value().one_time_pq.size() == 1,
                    "acquire returns exactly one EC and PQ one-time prekey")) {
      return false;
    }
    auto ec_insert = used_ec_ids.insert(bundle.value().one_time_ec.front().id);
    auto pq_insert = used_pq_ids.insert(bundle.value().one_time_pq.front().id);
    if (!AssertTrue(ec_insert.second && pq_insert.second,
                    "acquire returns unique one-time prekey ids")) {
      return false;
    }
    ++reserved_count;
  }
  if (!AssertTrue(reserved_count >= 2,
                  "multiple one-time prekeys can be reserved")) {
    return false;
  }

  auto depleted = server.AcquireBundleForSession(publisher_user);
  return AssertTrue(depleted.ok() && depleted.value().one_time_ec.empty() &&
                        depleted.value().one_time_pq.empty(),
                    "one-time prekeys are depleted after reservation");
}

bool TestInitialTamperAndDuplicateProtection() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  const std::string alice_user = "alice-initial";
  const std::string bob_user = "bob-initial";

  auto alice = Client::Create(alice_user);
  auto bob = Client::Create(bob_user);
  if (!AssertTrue(alice.ok() && bob.ok(), "alice/bob create")) {
    return false;
  }

  auto alice_client = alice.take_value();
  auto bob_client = bob.take_value();
  if (!AssertTrue(alice_client.PublishPrekeys(&server).ok(), "alice publish")) {
    return false;
  }
  if (!AssertTrue(bob_client.PublishPrekeys(&server).ok(), "bob publish")) {
    return false;
  }
  auto init_unverified = alice_client.InitiateSession(&server, bob_user, "hello bob");
  if (!AssertTrue(!init_unverified.ok(), "alice initiate blocked before verify")) {
    return false;
  }
  auto bob_safety = alice_client.GetPeerSafetyNumber(bob_user);
  if (!AssertTrue(bob_safety.ok(), "alice reads bob safety")) {
    return false;
  }
  if (!AssertTrue(alice_client.VerifyPeerSafetyNumber(bob_user, bob_safety.value()).ok(),
                  "alice verifies bob safety")) {
    return false;
  }
  if (!AssertTrue(alice_client.InitiateSession(&server, bob_user, "hello bob").ok(),
                  "alice initiate")) {
    return false;
  }

  auto drained = server.DrainInbox(bob_user);
  if (!AssertTrue(drained.ok() && drained.value().size() == 1,
                  "capture initial envelope for tamper/duplicate tests")) {
    return false;
  }

  auto envelope = drained.value().front().envelope;
  auto ack = server.DrainInbox(bob_user, drained.value().front().inbox_id);
  if (!AssertTrue(ack.ok() && ack.value().empty(), "ack captured initial envelope")) {
    return false;
  }

  auto tampered = envelope;
  if (!tampered.initial.has_value()) {
    return AssertTrue(false, "captured envelope has initial payload");
  }
  tampered.initial->session_id = "tampered-session-id";
  if (!AssertTrue(server.EnqueueEnvelope(bob_user, tampered).ok(),
                  "enqueue tampered initial envelope")) {
    return false;
  }
  auto tampered_result = bob_client.ProcessInbox(&server);
  if (!AssertTrue(!tampered_result.ok() &&
                      Contains(tampered_result.error(), "transcript hash mismatch"),
                  "tampered session_id is rejected by transcript binding")) {
    return false;
  }
  auto poisoned_page = server.DrainInbox(bob_user);
  if (!AssertTrue(poisoned_page.ok() && !poisoned_page.value().empty(),
                  "inspect poisoned inbox after tampered initial")) {
    return false;
  }
  auto drop_poison =
      server.DrainInbox(bob_user, poisoned_page.value().front().inbox_id);
  if (!AssertTrue(drop_poison.ok(), "drop tampered initial envelope")) {
    return false;
  }

  if (!AssertTrue(server.EnqueueEnvelope(bob_user, envelope).ok(),
                  "enqueue valid initial envelope")) {
    return false;
  }
  auto unverified = bob_client.ProcessInbox(&server);
  if (!AssertTrue(!unverified.ok(), "bob blocks unverified alice")) {
    return false;
  }
  auto alice_safety = bob_client.GetPeerSafetyNumber(alice_user);
  if (!AssertTrue(alice_safety.ok(), "bob reads alice safety")) {
    return false;
  }
  if (!AssertTrue(bob_client.VerifyPeerSafetyNumber(alice_user, alice_safety.value()).ok(),
                  "bob verifies alice safety")) {
    return false;
  }
  auto accepted = bob_client.ProcessInbox(&server);
  if (!AssertTrue(accepted.ok() && accepted.value().size() == 1 &&
                      accepted.value().front() == "hello bob",
                  "valid initial is delivered after verification")) {
    return false;
  }
  auto ack_deliver = bob_client.ProcessInbox(&server);
  if (!AssertTrue(ack_deliver.ok() && ack_deliver.value().empty(),
                  "ack committed after valid initial")) {
    return false;
  }

  if (!AssertTrue(server.EnqueueEnvelope(bob_user, envelope).ok(),
                  "enqueue duplicate initial envelope")) {
    return false;
  }
  auto duplicate_result = bob_client.ProcessInbox(&server);
  if (!AssertTrue(!duplicate_result.ok() &&
                      Contains(duplicate_result.error(), "duplicate initial"),
                  "duplicate initial replay rejected")) {
    return false;
  }
  auto duplicate_page = server.DrainInbox(bob_user);
  if (!AssertTrue(duplicate_page.ok() && !duplicate_page.value().empty(),
                  "inspect duplicate initial envelope in inbox")) {
    return false;
  }
  auto drop_duplicate =
      server.DrainInbox(bob_user, duplicate_page.value().front().inbox_id);
  if (!AssertTrue(drop_duplicate.ok(), "drop duplicate initial envelope")) {
    return false;
  }

  auto empty = bob_client.ProcessInbox(&server);
  return AssertTrue(empty.ok() && empty.value().empty(),
                    "no plaintext after duplicate replay cleanup");
}

bool TestInvalidInitialDoesNotBurnOneTimePrekeys() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  const std::string alice_user = "alice-opk-burn";
  const std::string bob_user = "bob-opk-burn";

  auto alice_result = Client::Create(alice_user);
  auto bob_result = Client::Create(bob_user);
  if (!AssertTrue(alice_result.ok() && bob_result.ok(), "create opk-burn clients")) {
    return false;
  }
  auto alice = alice_result.take_value();
  auto bob = bob_result.take_value();
  if (!AssertTrue(alice.PublishPrekeys(&server).ok() && bob.PublishPrekeys(&server).ok(),
                  "publish prekeys for opk-burn test")) {
    return false;
  }

  auto init_unverified = alice.InitiateSession(&server, bob_user, "hello");
  if (!AssertTrue(!init_unverified.ok(), "initiate blocked before verify in opk-burn test")) {
    return false;
  }
  auto bob_safety = alice.GetPeerSafetyNumber(bob_user);
  if (!AssertTrue(bob_safety.ok(), "alice reads bob safety in opk-burn test")) {
    return false;
  }
  if (!AssertTrue(alice.VerifyPeerSafetyNumber(bob_user, bob_safety.value()).ok(),
                  "alice verifies bob safety in opk-burn test")) {
    return false;
  }
  if (!AssertTrue(alice.InitiateSession(&server, bob_user, "hello").ok(),
                  "alice initiates opk-burn session")) {
    return false;
  }

  auto captured = server.DrainInbox(bob_user);
  if (!AssertTrue(captured.ok() && captured.value().size() == 1,
                  "capture initial for opk-burn test")) {
    return false;
  }
  auto envelope = captured.value().front().envelope;
  auto clear_captured = server.DrainInbox(bob_user, captured.value().front().inbox_id);
  if (!AssertTrue(clear_captured.ok(), "clear captured inbox entry")) {
    return false;
  }

  if (!AssertTrue(server.EnqueueEnvelope(bob_user, envelope).ok(),
                  "enqueue initial to learn identity")) {
    return false;
  }
  auto bob_unverified = bob.ProcessInbox(&server);
  if (!AssertTrue(!bob_unverified.ok(), "bob blocks unverified alice in opk-burn test")) {
    return false;
  }
  auto alice_safety = bob.GetPeerSafetyNumber(alice_user);
  if (!AssertTrue(alice_safety.ok(), "bob reads alice safety in opk-burn test")) {
    return false;
  }
  if (!AssertTrue(bob.VerifyPeerSafetyNumber(alice_user, alice_safety.value()).ok(),
                  "bob verifies alice safety in opk-burn test")) {
    return false;
  }
  auto pending = server.DrainInbox(bob_user);
  if (!AssertTrue(pending.ok() && pending.value().size() == 1,
                  "read pending initial before tamper")) {
    return false;
  }
  auto drop_pending = server.DrainInbox(bob_user, pending.value().front().inbox_id);
  if (!AssertTrue(drop_pending.ok(), "drop pending initial before tamper")) {
    return false;
  }

  auto tampered = envelope;
  if (!AssertTrue(tampered.initial.has_value(),
                  "captured envelope carries initial payload in opk-burn test")) {
    return false;
  }
  if (!AssertTrue(!tampered.initial->initial_ciphertext.empty(),
                  "captured initial has ciphertext for opk-burn tamper")) {
    return false;
  }
  tampered.initial->initial_ciphertext[0] ^= 0x01;
  if (!AssertTrue(server.EnqueueEnvelope(bob_user, tampered).ok() &&
                      server.EnqueueEnvelope(bob_user, envelope).ok(),
                  "enqueue tampered + valid initial sequence")) {
    return false;
  }

  auto tampered_result = bob.ProcessInbox(&server);
  if (!AssertTrue(!tampered_result.ok() &&
                      Contains(tampered_result.error(), "initial payload decrypt failed"),
                  "tampered initial fails after prekey lookup during payload decrypt")) {
    return false;
  }
  auto tampered_page = server.DrainInbox(bob_user);
  if (!AssertTrue(tampered_page.ok() && !tampered_page.value().empty(),
                  "inspect tampered page before recovery")) {
    return false;
  }
  auto drop_tampered =
      server.DrainInbox(bob_user, tampered_page.value().front().inbox_id);
  if (!AssertTrue(drop_tampered.ok(), "drop tampered initial for recovery")) {
    return false;
  }

  auto recovered = bob.ProcessInbox(&server);
  return AssertTrue(recovered.ok() && recovered.value().size() == 1 &&
                        recovered.value().front() == "hello",
                    "valid initial still succeeds after tampered initial");
}

bool TestAuthChallengeConsumptionAndRateLimits() {
  using pqchat::crypto::MlDsa65;
  using pqchat::protocol::AuthBeginRequest;
  using pqchat::protocol::AuthFinishRequest;
  using pqchat::protocol::BuildTransportAuthSignInput;
  using pqchat::protocol::RegisterRequest;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  auto auth_key = MlDsa65::GenerateKeyPair();
  if (!AssertTrue(auth_key.ok(), "transport auth keygen")) {
    return false;
  }

  RegisterRequest register_request;
  register_request.user_id = "auth-user";
  register_request.transport_auth_public_key = auth_key.value().public_key;
  auto register_proof = BuildRegisterProof(register_request.user_id, auth_key.value());
  if (!AssertTrue(register_proof.ok(), "register proof auth-user")) {
    return false;
  }
  register_request.proof_signature_mldsa65 = register_proof.take_value();
  if (!AssertTrue(server.RegisterTransportIdentity(register_request).ok(),
                  "register auth-user")) {
    return false;
  }

  AuthBeginRequest begin_request;
  begin_request.user_id = "auth-user";
  begin_request.client_nonce = std::vector<uint8_t>(32, 0x11);
  auto begin = server.BeginTransportAuthentication(begin_request);
  if (!AssertTrue(begin.ok(), "auth begin")) {
    return false;
  }

  AuthFinishRequest finish_bad;
  finish_bad.user_id = begin_request.user_id;
  finish_bad.challenge_id = begin.value().challenge_id;
  finish_bad.client_nonce = begin_request.client_nonce;
  finish_bad.server_nonce = begin.value().server_nonce;
  finish_bad.expires_at_unix = begin.value().expires_at_unix;
  finish_bad.signature_mldsa65 = std::vector<uint8_t>(128, 0xAA);
  auto bad_finish = server.FinishTransportAuthentication(finish_bad);
  if (!AssertTrue(!bad_finish.ok() &&
                      Contains(bad_finish.error(), "auth signature invalid"),
                  "first bad auth finish attempt fails")) {
    return false;
  }

  auto sign_input = BuildTransportAuthSignInput(begin_request.user_id,
                                                begin_request.client_nonce,
                                                begin.value().server_nonce,
                                                begin.value().challenge_id,
                                                begin.value().expires_at_unix);
  auto signature = MlDsa65::Sign(auth_key.value().private_key.get(), sign_input);
  if (!AssertTrue(signature.ok(), "valid auth signature")) {
    return false;
  }
  AuthFinishRequest finish_retry = finish_bad;
  finish_retry.signature_mldsa65 = signature.take_value();
  auto retry_finish = server.FinishTransportAuthentication(finish_retry);
  if (!AssertTrue(!retry_finish.ok() &&
                      Contains(retry_finish.error(), "challenge"),
                  "challenge is consumed after first finish attempt")) {
    return false;
  }

  RegisterRequest begin_limit_register;
  begin_limit_register.user_id = "begin-limit-user";
  begin_limit_register.transport_auth_public_key = auth_key.value().public_key;
  auto begin_limit_proof = BuildRegisterProof(begin_limit_register.user_id, auth_key.value());
  if (!AssertTrue(begin_limit_proof.ok(), "register proof begin-limit-user")) {
    return false;
  }
  begin_limit_register.proof_signature_mldsa65 = begin_limit_proof.take_value();
  if (!AssertTrue(server.RegisterTransportIdentity(begin_limit_register).ok(),
                  "register begin-limit-user")) {
    return false;
  }
  for (int i = 0; i < 30; ++i) {
    AuthBeginRequest req;
    req.user_id = begin_limit_register.user_id;
    req.client_nonce = std::vector<uint8_t>(32, static_cast<uint8_t>(i));
    if (!AssertTrue(server.BeginTransportAuthentication(req).ok(),
                    "auth begin below rate limit")) {
      return false;
    }
  }
  AuthBeginRequest req_last;
  req_last.user_id = begin_limit_register.user_id;
  req_last.client_nonce = std::vector<uint8_t>(32, 0xEE);
  auto begin_limited = server.BeginTransportAuthentication(req_last);
  if (!AssertTrue(!begin_limited.ok() &&
                      Contains(begin_limited.error(), "rate limit"),
                  "auth begin rate limit enforced")) {
    return false;
  }

  RegisterRequest finish_limit_register;
  finish_limit_register.user_id = "finish-limit-user";
  finish_limit_register.transport_auth_public_key = auth_key.value().public_key;
  auto finish_limit_proof = BuildRegisterProof(finish_limit_register.user_id, auth_key.value());
  if (!AssertTrue(finish_limit_proof.ok(), "register proof finish-limit-user")) {
    return false;
  }
  finish_limit_register.proof_signature_mldsa65 = finish_limit_proof.take_value();
  if (!AssertTrue(server.RegisterTransportIdentity(finish_limit_register).ok(),
                  "register finish-limit-user")) {
    return false;
  }
  for (int i = 0; i < 30; ++i) {
    AuthFinishRequest req;
    req.user_id = finish_limit_register.user_id;
    req.challenge_id = std::string(30, 'a') +
                       (i % 2 == 0 ? "0a" : "0b");
    req.client_nonce = std::vector<uint8_t>(32, 0x10);
    req.server_nonce = std::vector<uint8_t>(32, 0x20);
    req.expires_at_unix = 1;
    req.signature_mldsa65 = std::vector<uint8_t>(128, 0x30);
    auto finish = server.FinishTransportAuthentication(req);
    if (!AssertTrue(!finish.ok(), "auth finish fails before rate limit")) {
      return false;
    }
  }
  AuthFinishRequest finish_last;
  finish_last.user_id = finish_limit_register.user_id;
  finish_last.challenge_id = std::string(32, 'c');
  finish_last.client_nonce = std::vector<uint8_t>(32, 0x10);
  finish_last.server_nonce = std::vector<uint8_t>(32, 0x20);
  finish_last.expires_at_unix = 1;
  finish_last.signature_mldsa65 = std::vector<uint8_t>(128, 0x30);
  auto finish_limited = server.FinishTransportAuthentication(finish_last);
  return AssertTrue(!finish_limited.ok() &&
                        Contains(finish_limited.error(), "rate limit"),
                    "auth finish rate limit enforced");
}

bool TestRotationRevokesSessionsAndMasksUnknownUser() {
  using pqchat::crypto::MlDsa65;
  using pqchat::protocol::AuthBeginRequest;
  using pqchat::protocol::AuthFinishRequest;
  using pqchat::protocol::BuildTransportAuthSignInput;
  using pqchat::protocol::RegisterRequest;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  const std::string user_id = "rotate-user";

  auto key_v1 = MlDsa65::GenerateKeyPair();
  auto key_v2 = MlDsa65::GenerateKeyPair();
  if (!AssertTrue(key_v1.ok() && key_v2.ok(), "rotation test keygen")) {
    return false;
  }

  RegisterRequest register_v1;
  register_v1.user_id = user_id;
  register_v1.transport_auth_public_key = key_v1.value().public_key;
  auto proof_v1 = BuildRegisterProof(user_id, key_v1.value());
  if (!AssertTrue(proof_v1.ok(), "rotation test register proof v1")) {
    return false;
  }
  register_v1.proof_signature_mldsa65 = proof_v1.take_value();
  if (!AssertTrue(server.RegisterTransportIdentity(register_v1).ok(),
                  "rotation test register v1")) {
    return false;
  }

  AuthBeginRequest begin_v1;
  begin_v1.user_id = user_id;
  begin_v1.client_nonce = std::vector<uint8_t>(32, 0x41);
  auto begin_v1_resp = server.BeginTransportAuthentication(begin_v1);
  if (!AssertTrue(begin_v1_resp.ok(), "rotation test auth begin v1")) {
    return false;
  }
  auto sign_input_v1 = BuildTransportAuthSignInput(user_id,
                                                   begin_v1.client_nonce,
                                                   begin_v1_resp.value().server_nonce,
                                                   begin_v1_resp.value().challenge_id,
                                                   begin_v1_resp.value().expires_at_unix);
  auto sig_v1 = MlDsa65::Sign(key_v1.value().private_key.get(), sign_input_v1);
  if (!AssertTrue(sig_v1.ok(), "rotation test auth sign v1")) {
    return false;
  }
  AuthFinishRequest finish_v1;
  finish_v1.user_id = user_id;
  finish_v1.challenge_id = begin_v1_resp.value().challenge_id;
  finish_v1.client_nonce = begin_v1.client_nonce;
  finish_v1.server_nonce = begin_v1_resp.value().server_nonce;
  finish_v1.expires_at_unix = begin_v1_resp.value().expires_at_unix;
  finish_v1.signature_mldsa65 = sig_v1.take_value();
  auto finish_v1_resp = server.FinishTransportAuthentication(finish_v1);
  if (!AssertTrue(finish_v1_resp.ok(), "rotation test auth finish v1")) {
    return false;
  }
  auto token_before_rotation = finish_v1_resp.value().session_token;
  if (!AssertTrue(server.AuthenticateSessionToken(token_before_rotation).ok(),
                  "session is valid before key rotation")) {
    return false;
  }

  RegisterRequest rotate_request;
  rotate_request.user_id = user_id;
  rotate_request.transport_auth_public_key = key_v2.value().public_key;
  auto rotate_proof = BuildRegisterProof(user_id, key_v2.value());
  if (!AssertTrue(rotate_proof.ok(), "rotation test register proof v2")) {
    return false;
  }
  rotate_request.proof_signature_mldsa65 = rotate_proof.take_value();
  auto rotate_sig = BuildRotateProof(user_id, key_v1.value(), key_v2.value().public_key);
  if (!AssertTrue(rotate_sig.ok(), "rotation test rotate signature")) {
    return false;
  }
  rotate_request.rotation_signature_mldsa65 = rotate_sig.take_value();
  if (!AssertTrue(server.RegisterTransportIdentity(rotate_request).ok(),
                  "rotation test register v2 with rotation signature")) {
    return false;
  }

  auto auth_after_rotation = server.AuthenticateSessionToken(token_before_rotation);
  if (!AssertTrue(!auth_after_rotation.ok(),
                  "rotation revokes existing sessions")) {
    return false;
  }

  AuthBeginRequest unknown_begin;
  unknown_begin.user_id = "missing-rotate-user";
  unknown_begin.client_nonce = std::vector<uint8_t>(32, 0x22);
  auto unknown_begin_result = server.BeginTransportAuthentication(unknown_begin);
  if (!AssertTrue(!unknown_begin_result.ok() &&
                      Contains(unknown_begin_result.error(), "authentication failed") &&
                      !Contains(unknown_begin_result.error(), "unknown user"),
                  "unknown-user auth begin is masked")) {
    return false;
  }

  AuthBeginRequest begin_v2;
  begin_v2.user_id = user_id;
  begin_v2.client_nonce = std::vector<uint8_t>(32, 0x42);
  auto begin_v2_resp = server.BeginTransportAuthentication(begin_v2);
  if (!AssertTrue(begin_v2_resp.ok(), "rotation test auth begin v2")) {
    return false;
  }
  auto sign_input_v2 = BuildTransportAuthSignInput(user_id,
                                                   begin_v2.client_nonce,
                                                   begin_v2_resp.value().server_nonce,
                                                   begin_v2_resp.value().challenge_id,
                                                   begin_v2_resp.value().expires_at_unix);
  auto sig_v2 = MlDsa65::Sign(key_v2.value().private_key.get(), sign_input_v2);
  if (!AssertTrue(sig_v2.ok(), "rotation test auth sign v2")) {
    return false;
  }
  AuthFinishRequest finish_v2;
  finish_v2.user_id = user_id;
  finish_v2.challenge_id = begin_v2_resp.value().challenge_id;
  finish_v2.client_nonce = begin_v2.client_nonce;
  finish_v2.server_nonce = begin_v2_resp.value().server_nonce;
  finish_v2.expires_at_unix = begin_v2_resp.value().expires_at_unix;
  finish_v2.signature_mldsa65 = sig_v2.take_value();
  auto finish_v2_resp = server.FinishTransportAuthentication(finish_v2);
  return AssertTrue(finish_v2_resp.ok(),
                    "authentication succeeds with rotated key");
}

bool TestUnverifiedPeerIdentityPersistsAcrossRestart() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  const std::string alice_user = "alice-unverified-persist";
  const std::string bob_user = "bob-unverified-persist";
  auto alice_result = Client::Create(alice_user);
  auto bob_result = Client::Create(bob_user);
  if (!AssertTrue(alice_result.ok() && bob_result.ok(),
                  "create clients for unverified identity persistence")) {
    return false;
  }

  auto alice = alice_result.take_value();
  auto bob = bob_result.take_value();
  if (!AssertTrue(bob.PublishPrekeys(&server).ok(),
                  "publish bob prekeys for unverified identity persistence")) {
    return false;
  }

  auto init = alice.InitiateSession(&server, bob_user, "hello");
  if (!AssertTrue(!init.ok(), "alice blocked before verifying bob identity")) {
    return false;
  }
  auto safety_before_restart = alice.GetPeerSafetyNumber(bob_user);
  if (!AssertTrue(safety_before_restart.ok(),
                  "alice reads bob safety before restart")) {
    return false;
  }

  auto alice_reloaded = Client::Create(alice_user);
  if (!AssertTrue(alice_reloaded.ok(), "reload alice with unverified peer identity")) {
    return false;
  }
  auto safety_after_restart = alice_reloaded.value().GetPeerSafetyNumber(bob_user);
  return AssertTrue(safety_after_restart.ok() &&
                        safety_after_restart.value() == safety_before_restart.value(),
                    "unverified peer identity safety number persists across restart");
}

}  // namespace

int main() {
  char state_dir_template[] = "/tmp/pqchat_security_state_XXXXXX";
  int state_fd = mkstemp(state_dir_template);
  if (state_fd < 0) {
    std::cerr << "FAIL: mkstemp for isolated state dir\n";
    return 1;
  }
  close(state_fd);
  unlink(state_dir_template);
  if (mkdir(state_dir_template, 0700) != 0) {
    std::cerr << "FAIL: mkdir for isolated state dir\n";
    return 1;
  }
  if (setenv("PQCHAT_STATE_DIR", state_dir_template, 1) != 0) {
    std::cerr << "FAIL: setenv PQCHAT_STATE_DIR\n";
    std::filesystem::remove_all(state_dir_template);
    return 1;
  }
  if (setenv("PQCHAT_STATE_PASSPHRASE", "security-test-passphrase", 1) != 0) {
    std::cerr << "FAIL: setenv PQCHAT_STATE_PASSPHRASE\n";
    std::filesystem::remove_all(state_dir_template);
    return 1;
  }

  bool ok = true;
  ok &= TestOpkRequirementOnInitiator();
  ok &= TestAcquireBundleReservesOneTimePrekeys();
  ok &= TestInitialTamperAndDuplicateProtection();
  ok &= TestInvalidInitialDoesNotBurnOneTimePrekeys();
  ok &= TestAuthChallengeConsumptionAndRateLimits();
  ok &= TestRotationRevokesSessionsAndMasksUnknownUser();
  ok &= TestUnverifiedPeerIdentityPersistsAcrossRestart();
  unsetenv("PQCHAT_STATE_DIR");
  unsetenv("PQCHAT_STATE_PASSPHRASE");
  std::filesystem::remove_all(state_dir_template);
  if (!ok) {
    return 1;
  }
  std::cout << "PASS: security protocol test suite\n";
  return 0;
}
