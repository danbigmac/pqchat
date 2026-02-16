#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <sstream>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pqchat/client/client.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/protocol/transport_auth.h"
#include "pqchat/server/in_memory_server.h"
#include "pqchat/server/tcp_wire.h"

namespace {

bool AssertTrue(bool value, const std::string& label) {
  if (!value) {
    std::cerr << "FAIL: " << label << "\n";
    return false;
  }
  return true;
}

void StoreU32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(value & 0xFF);
}

std::string HexEncode(const std::vector<uint8_t>& bytes) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : bytes) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
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

}  // namespace

int main() {
  char state_dir_template[] = "/tmp/pqchat_integration_state_XXXXXX";
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
  if (setenv("PQCHAT_STATE_PASSPHRASE", "integration-test-passphrase", 1) != 0) {
    std::cerr << "FAIL: setenv PQCHAT_STATE_PASSPHRASE\n";
    std::filesystem::remove_all(state_dir_template);
    return 1;
  }

  using pqchat::client::Client;
  using pqchat::crypto::MlDsa65;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  bool ok = true;

  int sockets[2] = {-1, -1};
  ok &= AssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
                   "socketpair for frame-limit test");
  if (!ok) {
    return 1;
  }
  uint8_t oversized_header[8];
  StoreU32(oversized_header, 7);
  StoreU32(oversized_header + 4, pqchat::server::kMaxFramePayloadBytes + 1);
  ok &= AssertTrue(send(sockets[0], oversized_header, sizeof(oversized_header), 0) ==
                       static_cast<ssize_t>(sizeof(oversized_header)),
                   "write oversized frame header");
  auto oversized_frame = pqchat::server::ReadFrame(sockets[1]);
  ok &= AssertTrue(!oversized_frame.ok() &&
                       oversized_frame.error() == "frame payload too large",
                   "oversized frame rejected");
  close(sockets[0]);
  close(sockets[1]);
  if (!ok) {
    return 1;
  }

  auto auth_key = MlDsa65::GenerateKeyPair();
  ok &= AssertTrue(auth_key.ok(), "transport auth keygen");
  if (!ok) {
    return 1;
  }

  const std::string provisioning_secret = "test-provisioning-secret";
  InMemoryServer gated_server(provisioning_secret);
  pqchat::protocol::RegisterRequest bad_register_request;
  bad_register_request.user_id = "alice";
  bad_register_request.transport_auth_public_key = auth_key.value().public_key;
  bad_register_request.registration_token = "bad-token";
  auto bad_register_proof = BuildRegisterProof(bad_register_request.user_id, auth_key.value());
  ok &= AssertTrue(bad_register_proof.ok(), "build bad registration proof");
  bad_register_request.proof_signature_mldsa65 = bad_register_proof.ok()
      ? bad_register_proof.value()
      : std::vector<uint8_t>{};
  auto bad_register_status = gated_server.RegisterTransportIdentity(bad_register_request);
  ok &= AssertTrue(!bad_register_status.ok(),
                   "registration rejects non-user-bound provisioning token");

  pqchat::protocol::RegisterRequest good_register_request;
  good_register_request.user_id = "alice";
  good_register_request.transport_auth_public_key = auth_key.value().public_key;
  good_register_request.registration_token =
      DeriveRegistrationToken(provisioning_secret, good_register_request.user_id);
  auto good_register_proof = BuildRegisterProof(good_register_request.user_id, auth_key.value());
  ok &= AssertTrue(good_register_proof.ok(), "build good registration proof");
  good_register_request.proof_signature_mldsa65 = good_register_proof.ok()
      ? good_register_proof.value()
      : std::vector<uint8_t>{};
  auto good_register_status = gated_server.RegisterTransportIdentity(good_register_request);
  ok &= AssertTrue(good_register_status.ok(),
                   "registration accepts user-bound provisioning token");
  if (!ok) {
    return 1;
  }

  pqchat::protocol::RegisterRequest register_request;
  register_request.user_id = "transport-user";
  register_request.transport_auth_public_key = auth_key.value().public_key;
  auto register_proof = BuildRegisterProof(register_request.user_id, auth_key.value());
  ok &= AssertTrue(register_proof.ok(), "build transport register proof");
  register_request.proof_signature_mldsa65 =
      register_proof.ok() ? register_proof.value() : std::vector<uint8_t>{};
  auto register_status = server.RegisterTransportIdentity(register_request);
  ok &= AssertTrue(register_status.ok(), "register transport identity");

  pqchat::protocol::AuthBeginRequest begin_request;
  begin_request.user_id = "transport-user";
  begin_request.client_nonce = std::vector<uint8_t>(32, 0x42);
  auto begin_response = server.BeginTransportAuthentication(begin_request);
  ok &= AssertTrue(begin_response.ok(), "auth begin");
  if (!ok) {
    return 1;
  }

  auto sign_input = pqchat::protocol::BuildTransportAuthSignInput(
      begin_request.user_id,
      begin_request.client_nonce,
      begin_response.value().server_nonce,
      begin_response.value().challenge_id,
      begin_response.value().expires_at_unix);
  auto signature = MlDsa65::Sign(auth_key.value().private_key.get(), sign_input);
  ok &= AssertTrue(signature.ok(), "auth signature");
  if (!ok) {
    return 1;
  }

  pqchat::protocol::AuthFinishRequest finish_request;
  finish_request.user_id = begin_request.user_id;
  finish_request.challenge_id = begin_response.value().challenge_id;
  finish_request.client_nonce = begin_request.client_nonce;
  finish_request.server_nonce = begin_response.value().server_nonce;
  finish_request.expires_at_unix = begin_response.value().expires_at_unix;
  finish_request.signature_mldsa65 = signature.take_value();

  auto finish_response = server.FinishTransportAuthentication(finish_request);
  ok &= AssertTrue(finish_response.ok(), "auth finish");
  ok &= AssertTrue(finish_response.ok() && !finish_response.value().session_token.empty(),
                   "auth token issued");

  auto session_user =
      server.AuthenticateSessionToken(finish_response.value().session_token);
  ok &= AssertTrue(session_user.ok() && session_user.value() == "transport-user",
                   "session validates to user");
  if (!ok) {
    return 1;
  }

  auto alice_result = Client::Create("alice");
  auto bob_result = Client::Create("bob");

  ok &= AssertTrue(alice_result.ok(), "alice create");
  ok &= AssertTrue(bob_result.ok(), "bob create");
  if (!ok) {
    return 1;
  }

  auto alice = alice_result.take_value();
  auto bob = bob_result.take_value();

  auto bad_suite_bundle = alice.BuildPrekeyBundle();
  bad_suite_bundle.cipher_suite = "X25519+BAD";
  auto bad_suite_publish = server.PublishBundle(bad_suite_bundle);
  ok &= AssertTrue(!bad_suite_publish.ok(), "reject unsupported bundle cipher suite");

  auto bad_version_bundle = alice.BuildPrekeyBundle();
  bad_version_bundle.version = "pqchat-v999";
  auto bad_version_publish = server.PublishBundle(bad_version_bundle);
  ok &= AssertTrue(!bad_version_publish.ok(), "reject unsupported bundle version");

  auto tampered_bundle = alice.BuildPrekeyBundle();
  if (!tampered_bundle.identity_dh_public_key.empty()) {
    tampered_bundle.identity_dh_public_key[0] ^= 0x01;
  }
  auto tampered_publish = server.PublishBundle(tampered_bundle);
  ok &= AssertTrue(!tampered_publish.ok(),
                   "reject bundle with invalid full-bundle signature");

  auto tampered_opk_bundle = alice.BuildPrekeyBundle();
  if (!tampered_opk_bundle.one_time_ec.empty() &&
      !tampered_opk_bundle.one_time_ec[0].public_key.empty()) {
    tampered_opk_bundle.one_time_ec[0].public_key[0] ^= 0x01;
  }
  auto tampered_opk_publish = server.PublishBundle(tampered_opk_bundle);
  ok &= AssertTrue(tampered_opk_publish.ok(),
                   "publish accepts one-time prekey list updates");
  if (!ok) {
    return 1;
  }

  ok &= AssertTrue(alice.PublishPrekeys(&server).ok(), "alice publish prekeys");
  ok &= AssertTrue(bob.PublishPrekeys(&server).ok(), "bob publish prekeys");

  auto init_unverified = alice.InitiateSession(&server, "bob", "hello bob");
  ok &= AssertTrue(!init_unverified.ok(), "alice initiate blocked until peer verified");
  auto bob_safety_for_alice = alice.GetPeerSafetyNumber("bob");
  ok &= AssertTrue(bob_safety_for_alice.ok(), "alice reads bob safety number");
  ok &= AssertTrue(alice.VerifyPeerSafetyNumber("bob", bob_safety_for_alice.value()).ok(),
                   "alice verifies bob safety number");
  auto init = alice.InitiateSession(&server, "bob", "hello bob");
  ok &= AssertTrue(init.ok(), "alice initiate session");
  if (!ok) {
    return 1;
  }

  auto bob_unverified = bob.ProcessInbox(&server);
  ok &= AssertTrue(!bob_unverified.ok(), "bob blocks unverified alice identity");
  auto alice_safety_for_bob = bob.GetPeerSafetyNumber("alice");
  ok &= AssertTrue(alice_safety_for_bob.ok(), "bob reads alice safety number");
  ok &= AssertTrue(bob.VerifyPeerSafetyNumber("alice", alice_safety_for_bob.value()).ok(),
                   "bob verifies alice safety number");

  auto bob_inbox = bob.ProcessInbox(&server);
  ok &= AssertTrue(bob_inbox.ok(), "bob process initial message");
  ok &= AssertTrue(bob_inbox.ok() && bob_inbox.value().size() == 1,
                   "bob got one initial plaintext");
  ok &= AssertTrue(bob_inbox.ok() && bob_inbox.value()[0] == "hello bob",
                   "bob plaintext matches");

  auto reply = bob.SendMessage(&server, "alice", "hello alice");
  ok &= AssertTrue(reply.ok(), "bob send reply");

  auto alice_inbox = alice.ProcessInbox(&server);
  ok &= AssertTrue(alice_inbox.ok(), "alice process reply");
  ok &= AssertTrue(alice_inbox.ok() && alice_inbox.value().size() == 1,
                   "alice got one plaintext");
  ok &= AssertTrue(alice_inbox.ok() && alice_inbox.value()[0] == "hello alice",
                   "alice plaintext matches");

  auto msg1 = alice.SendMessage(&server, "bob", "message-1");
  ok &= AssertTrue(msg1.ok(), "alice send message-1");

  auto inbox_once_result = server.DrainInbox("bob");
  ok &= AssertTrue(inbox_once_result.ok(), "drain inbox for replay setup");
  ok &= AssertTrue(inbox_once_result.ok() && inbox_once_result.value().size() == 1,
                   "bob inbox has one message for replay test");
  if (!ok) {
    return 1;
  }
  auto inbox_once = inbox_once_result.take_value();
  auto ack_once_result = server.DrainInbox("bob", inbox_once.back().inbox_id);
  ok &= AssertTrue(ack_once_result.ok(), "ack replay setup inbox item");
  ok &= AssertTrue(ack_once_result.ok() && ack_once_result.value().empty(),
                   "acked replay setup inbox is empty");
  if (!ok) {
    return 1;
  }

  // Re-inject identical ciphertext twice; the first copy should decrypt and the
  // duplicate should be ignored without failing the entire inbox poll.
  server.EnqueueEnvelope("bob", inbox_once[0].envelope);
  server.EnqueueEnvelope("bob", inbox_once[0].envelope);

  auto replay_result = bob.ProcessInbox(&server);
  ok &= AssertTrue(replay_result.ok(),
                   "replay duplicate does not fail entire inbox poll");
  ok &= AssertTrue(replay_result.ok() && replay_result.value().size() == 1 &&
                       replay_result.value()[0] == "message-1",
                   "replay duplicate still delivers valid message once");
  auto replay_cleanup_page = server.DrainInbox("bob");
  if (!replay_cleanup_page.ok()) {
    return 1;
  }
  if (!replay_cleanup_page.value().empty()) {
    auto replay_cleanup_ack =
        server.DrainInbox("bob", replay_cleanup_page.value().back().inbox_id);
    if (!replay_cleanup_ack.ok()) {
      return 1;
    }
  }

  auto msg2 = alice.SendMessage(&server, "bob", "message-2");
  ok &= AssertTrue(msg2.ok(), "alice send message-2");

  auto inbox_twice_result = server.DrainInbox("bob");
  ok &= AssertTrue(inbox_twice_result.ok(), "drain inbox for mixed-validity setup");
  ok &= AssertTrue(inbox_twice_result.ok() && inbox_twice_result.value().size() == 1,
                   "bob inbox has one message for mixed-validity test");
  if (!ok) {
    return 1;
  }
  auto inbox_twice = inbox_twice_result.take_value();
  auto ack_twice_result = server.DrainInbox("bob", inbox_twice.back().inbox_id);
  ok &= AssertTrue(ack_twice_result.ok(), "ack mixed-validity setup inbox item");
  ok &= AssertTrue(ack_twice_result.ok() && ack_twice_result.value().empty(),
                   "acked mixed-validity setup inbox is empty");
  if (!ok) {
    return 1;
  }

  auto valid_envelope = inbox_twice[0].envelope;
  auto invalid_envelope = valid_envelope;
  if (invalid_envelope.chat.has_value()) {
    invalid_envelope.chat->session_id = "wrong-session-id";
  }
  server.EnqueueEnvelope("bob", std::move(invalid_envelope));
  server.EnqueueEnvelope("bob", std::move(valid_envelope));

  auto mixed_result = bob.ProcessInbox(&server);
  ok &= AssertTrue(!mixed_result.ok(),
                   "invalid message in batch fails poll without dropping later messages");
  auto poisoned_page = server.DrainInbox("bob");
  ok &= AssertTrue(poisoned_page.ok() && !poisoned_page.value().empty(),
                   "inspect poisoned inbox page");
  auto drop_invalid = server.DrainInbox("bob", poisoned_page.value().front().inbox_id);
  ok &= AssertTrue(drop_invalid.ok(), "remove invalid envelope for recovery");
  auto mixed_recovered = bob.ProcessInbox(&server);
  ok &= AssertTrue(mixed_recovered.ok() && mixed_recovered.value().size() == 1 &&
                       mixed_recovered.value()[0] == "message-2",
                   "valid message is preserved after skipping invalid head item");

  constexpr int kBurstMessages = 150;
  for (int i = 0; i < kBurstMessages; ++i) {
    auto burst_send =
        alice.SendMessage(&server, "bob", "burst-" + std::to_string(i));
    ok &= AssertTrue(burst_send.ok(),
                     "alice send burst message " + std::to_string(i));
  }
  auto burst_result = bob.ProcessInbox(&server);
  ok &= AssertTrue(burst_result.ok(), "bob processes paged inbox burst");
  ok &= AssertTrue(burst_result.ok() &&
                       burst_result.value().size() == static_cast<size_t>(kBurstMessages),
                   "paged inbox poll drains all burst messages");
  ok &= AssertTrue(burst_result.ok() && !burst_result.value().empty() &&
                       burst_result.value().front() == "burst-0" &&
                       burst_result.value().back() == "burst-149",
                   "paged inbox burst preserves message order");
  if (!ok) {
    return 1;
  }

  auto alice_resume_result = Client::Create("alice-resume");
  auto bob_resume_result = Client::Create("bob-resume");
  ok &= AssertTrue(alice_resume_result.ok(), "alice-resume create");
  ok &= AssertTrue(bob_resume_result.ok(), "bob-resume create");
  if (!ok) {
    return 1;
  }

  auto alice_resume = alice_resume_result.take_value();
  ok &= AssertTrue(alice_resume.PublishPrekeys(&server).ok(), "alice-resume publish prekeys");
  if (!ok) {
    return 1;
  }

  {
    auto bob_resume = bob_resume_result.take_value();
    ok &= AssertTrue(bob_resume.PublishPrekeys(&server).ok(), "bob-resume publish prekeys");
    if (!ok) {
      return 1;
    }

    auto resume_init_unverified =
        alice_resume.InitiateSession(&server, "bob-resume", "resume-init");
    ok &= AssertTrue(!resume_init_unverified.ok(),
                     "alice-resume initiate blocked before verify");
    auto resume_bob_safety = alice_resume.GetPeerSafetyNumber("bob-resume");
    ok &= AssertTrue(resume_bob_safety.ok(), "alice-resume reads bob-resume safety");
    ok &= AssertTrue(alice_resume.VerifyPeerSafetyNumber("bob-resume",
                                                         resume_bob_safety.value()).ok(),
                     "alice-resume verifies bob-resume safety");
    ok &= AssertTrue(alice_resume.InitiateSession(&server, "bob-resume", "resume-init").ok(),
                     "alice-resume initiates session");
    if (!ok) {
      return 1;
    }

    auto resume_bob_unverified = bob_resume.ProcessInbox(&server);
    ok &= AssertTrue(!resume_bob_unverified.ok(),
                     "bob-resume blocks unverified alice-resume identity");
    auto resume_alice_safety = bob_resume.GetPeerSafetyNumber("alice-resume");
    ok &= AssertTrue(resume_alice_safety.ok(), "bob-resume reads alice-resume safety");
    ok &= AssertTrue(bob_resume.VerifyPeerSafetyNumber("alice-resume",
                                                       resume_alice_safety.value()).ok(),
                     "bob-resume verifies alice-resume safety");
    auto resume_bob_init = bob_resume.ProcessInbox(&server);
    ok &= AssertTrue(resume_bob_init.ok() && resume_bob_init.value().size() == 1 &&
                         resume_bob_init.value()[0] == "resume-init",
                     "bob-resume receives initial session plaintext");
    ok &= AssertTrue(bob_resume.SendMessage(&server, "alice-resume", "resume-online-ack").ok(),
                     "bob-resume sends pre-logout message");
    auto resume_alice_ack = alice_resume.ProcessInbox(&server);
    ok &= AssertTrue(resume_alice_ack.ok() && resume_alice_ack.value().size() == 1 &&
                         resume_alice_ack.value()[0] == "resume-online-ack",
                     "alice-resume receives pre-logout message");
    if (!ok) {
      return 1;
    }
  }

  constexpr int kOfflineQueuedMessages = 4;
  for (int i = 0; i < kOfflineQueuedMessages; ++i) {
    auto send_status = alice_resume.SendMessage(
        &server, "bob-resume", "queued-while-offline-" + std::to_string(i));
    ok &= AssertTrue(send_status.ok(),
                     "alice-resume sends queued message " + std::to_string(i));
  }
  if (!ok) {
    return 1;
  }

  auto bob_relogin_result = Client::Create("bob-resume");
  ok &= AssertTrue(bob_relogin_result.ok(), "bob-resume logs back in from persisted state");
  if (!ok) {
    return 1;
  }
  auto bob_relogin = bob_relogin_result.take_value();
  auto resumed_inbox = bob_relogin.ProcessInbox(&server);
  ok &= AssertTrue(resumed_inbox.ok() &&
                       resumed_inbox.value().size() ==
                           static_cast<size_t>(kOfflineQueuedMessages),
                   "bob-resume drains queued offline messages after login");
  ok &= AssertTrue(resumed_inbox.ok() && resumed_inbox.value().front() == "queued-while-offline-0" &&
                       resumed_inbox.value().back() == "queued-while-offline-3",
                   "queued offline messages preserve order across resume");
  if (!ok) {
    return 1;
  }

  ok &= AssertTrue(bob_relogin.SendMessage(&server, "alice-resume", "resume-after-login").ok(),
                   "bob-resume continues conversation after login");
  auto alice_after_resume = alice_resume.ProcessInbox(&server);
  ok &= AssertTrue(alice_after_resume.ok() && alice_after_resume.value().size() == 1 &&
                       alice_after_resume.value()[0] == "resume-after-login",
                   "alice-resume receives post-login message");
  ok &= AssertTrue(alice_resume.SendMessage(&server, "bob-resume", "resume-final").ok(),
                   "alice-resume sends final resume message");
  auto bob_final = bob_relogin.ProcessInbox(&server);
  ok &= AssertTrue(bob_final.ok() && bob_final.value().size() == 1 &&
                       bob_final.value()[0] == "resume-final",
                   "bob-resume receives final message after conversation resumes");

  unsetenv("PQCHAT_STATE_DIR");
  unsetenv("PQCHAT_STATE_PASSPHRASE");
  std::filesystem::remove_all(state_dir_template);
  if (!ok) {
    return 1;
  }

  std::cout << "PASS: integration test suite\n";
  return 0;
}
