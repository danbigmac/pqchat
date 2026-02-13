#include <iostream>
#include <string>
#include <vector>

#include "pqchat/client/client.h"
#include "pqchat/crypto/mldsa.h"
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

}  // namespace

int main() {
  using pqchat::client::Client;
  using pqchat::crypto::MlDsa65;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  bool ok = true;

  auto auth_key = MlDsa65::GenerateKeyPair();
  ok &= AssertTrue(auth_key.ok(), "transport auth keygen");
  if (!ok) {
    return 1;
  }

  pqchat::protocol::RegisterRequest register_request;
  register_request.user_id = "transport-user";
  register_request.transport_auth_public_key = auth_key.value().public_key;
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

  ok &= AssertTrue(alice.PublishPrekeys(&server).ok(), "alice publish prekeys");
  ok &= AssertTrue(bob.PublishPrekeys(&server).ok(), "bob publish prekeys");

  auto init = alice.InitiateSession(&server, "bob", "hello bob");
  ok &= AssertTrue(init.ok(), "alice initiate session");
  if (!ok) {
    return 1;
  }

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

  // Re-inject identical ciphertext twice; second copy should be rejected.
  server.EnqueueEnvelope("bob", inbox_once[0]);
  server.EnqueueEnvelope("bob", inbox_once[0]);

  auto replay_result = bob.ProcessInbox(&server);
  ok &= AssertTrue(!replay_result.ok(), "replay duplicate is rejected");

  if (!ok) {
    return 1;
  }

  std::cout << "PASS: integration test suite\n";
  return 0;
}
