#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "pqchat/client/client.h"
#include "pqchat/crypto/aead.h"
#include "pqchat/crypto/ed25519.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/crypto/mlkem.h"
#include "pqchat/crypto/x25519.h"
#include "pqchat/protocol/messages.h"
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

std::vector<uint8_t> Hex(const char* s) {
  std::vector<uint8_t> out;
  for (size_t i = 0; s[i] != '\0' && s[i + 1] != '\0'; i += 2) {
    auto nibble = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
      }
      if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + c - 'a');
      }
      if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(10 + c - 'A');
      }
      return 0;
    };
    out.push_back(static_cast<uint8_t>((nibble(s[i]) << 4) | nibble(s[i + 1])));
  }
  return out;
}

bool TestCryptoUnitsFromDesign() {
  using pqchat::crypto::AeadChaCha20Poly1305;
  using pqchat::crypto::Ed25519;
  using pqchat::crypto::HkdfSha256;
  using pqchat::crypto::MlDsa65;
  using pqchat::crypto::MlKem768;
  using pqchat::crypto::NonceFromCounter;
  using pqchat::crypto::X25519;

  auto ed = Ed25519::GenerateKeyPair();
  if (!AssertTrue(ed.ok(), "Ed25519 keygen")) {
    return false;
  }
  const std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
  auto ed_sig = Ed25519::Sign(ed.value().private_key, msg);
  if (!AssertTrue(ed_sig.ok(), "Ed25519 sign")) {
    return false;
  }
  if (!AssertTrue(Ed25519::Verify(ed.value().public_key, msg, ed_sig.value()).ok(),
                  "Ed25519 verify")) {
    return false;
  }
  auto tampered = msg;
  tampered[0] ^= 0x01;
  if (!AssertTrue(!Ed25519::Verify(ed.value().public_key, tampered, ed_sig.value()).ok(),
                  "Ed25519 tamper detect")) {
    return false;
  }

  auto ml = MlDsa65::GenerateKeyPair();
  if (!AssertTrue(ml.ok(), "ML-DSA keygen")) {
    return false;
  }
  auto ml_sig = MlDsa65::Sign(ml.value().private_key.get(), msg);
  if (!AssertTrue(ml_sig.ok(), "ML-DSA sign")) {
    return false;
  }
  if (!AssertTrue(MlDsa65::Verify(ml.value().public_key, msg, ml_sig.value()).ok(),
                  "ML-DSA verify")) {
    return false;
  }
  if (!AssertTrue(!MlDsa65::Verify(ml.value().public_key, tampered, ml_sig.value()).ok(),
                  "ML-DSA tamper detect")) {
    return false;
  }

  auto x_a = X25519::GenerateKeyPair();
  auto x_b = X25519::GenerateKeyPair();
  if (!AssertTrue(x_a.ok() && x_b.ok(), "X25519 keygen")) {
    return false;
  }
  auto s_ab = X25519::SharedSecret(x_a.value().private_key, x_b.value().public_key);
  auto s_ba = X25519::SharedSecret(x_b.value().private_key, x_a.value().public_key);
  if (!AssertTrue(s_ab.ok() && s_ba.ok() && s_ab.value() == s_ba.value(),
                  "X25519 shared secret consistency")) {
    return false;
  }

  auto kem = MlKem768::GenerateKeyPair();
  if (!AssertTrue(kem.ok(), "ML-KEM keygen")) {
    return false;
  }
  auto enc = MlKem768::Encapsulate(kem.value().public_key);
  if (!AssertTrue(enc.ok(), "ML-KEM encaps")) {
    return false;
  }
  auto dec = MlKem768::Decapsulate(kem.value().private_key.get(), enc.value().ciphertext);
  if (!AssertTrue(dec.ok() && dec.value() == enc.value().shared_secret,
                  "ML-KEM decaps consistency")) {
    return false;
  }

  auto hkdf = HkdfSha256(Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                         Hex("000102030405060708090a0b0c"),
                         Hex("f0f1f2f3f4f5f6f7f8f9"),
                         42);
  if (!AssertTrue(hkdf.ok(), "HKDF vector derive")) {
    return false;
  }
  if (!AssertTrue(hkdf.value() ==
                      Hex("3cb25f25faacd57a90434f64d0362f2a"
                          "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                          "34007208d5b887185865"),
                  "HKDF RFC5869 test vector")) {
    return false;
  }

  std::vector<uint8_t> key(32, 0x5A);
  std::vector<uint8_t> ad = {'a', 'd'};
  auto nonce = NonceFromCounter(12);
  auto ct = AeadChaCha20Poly1305::Seal(key, nonce, msg, ad);
  if (!AssertTrue(ct.ok(), "AEAD seal")) {
    return false;
  }
  auto opened = AeadChaCha20Poly1305::Open(key, nonce, ct.value(), ad);
  if (!AssertTrue(opened.ok() && opened.value() == msg, "AEAD open")) {
    return false;
  }
  auto tampered_ct = ct.value();
  tampered_ct[0] ^= 0x40;
  if (!AssertTrue(!AeadChaCha20Poly1305::Open(key, nonce, tampered_ct, ad).ok(),
                  "AEAD tamper detection")) {
    return false;
  }

  return true;
}

bool TestTamperedChatHeaderAssociatedDataRejected() {
  using pqchat::client::Client;
  using pqchat::protocol::EnvelopeType;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  auto alice = Client::Create("alice");
  auto bob = Client::Create("bob");
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
  auto init_unverified = alice_client.InitiateSession(&server, "bob", "init");
  if (!AssertTrue(!init_unverified.ok(), "initiate blocked before peer verify")) {
    return false;
  }
  auto bob_safety = alice_client.GetPeerSafetyNumber("bob");
  if (!AssertTrue(bob_safety.ok(), "alice reads bob safety")) {
    return false;
  }
  if (!AssertTrue(alice_client.VerifyPeerSafetyNumber("bob", bob_safety.value()).ok(),
                  "alice verifies bob safety")) {
    return false;
  }
  if (!AssertTrue(alice_client.InitiateSession(&server, "bob", "init").ok(),
                  "initiate")) {
    return false;
  }
  auto bob_first_unverified = bob_client.ProcessInbox(&server);
  if (!AssertTrue(!bob_first_unverified.ok(), "bob blocks unverified alice")) {
    return false;
  }
  auto alice_safety = bob_client.GetPeerSafetyNumber("alice");
  if (!AssertTrue(alice_safety.ok(), "bob reads alice safety")) {
    return false;
  }
  if (!AssertTrue(bob_client.VerifyPeerSafetyNumber("alice", alice_safety.value()).ok(),
                  "bob verifies alice safety")) {
    return false;
  }
  auto bob_first = bob_client.ProcessInbox(&server);
  if (!AssertTrue(bob_first.ok() && bob_first.value().size() == 1, "bob processes init")) {
    return false;
  }

  if (!AssertTrue(alice_client.SendMessage(&server, "bob", "secure-message").ok(),
                  "alice send")) {
    return false;
  }
  auto drained = server.DrainInbox("bob");
  if (!AssertTrue(drained.ok() && drained.value().size() == 1, "capture chat envelope")) {
    return false;
  }
  auto chat_env = drained.value().front().envelope;
  if (!AssertTrue(chat_env.type == EnvelopeType::kChat && chat_env.chat.has_value(),
                  "captured envelope is chat")) {
    return false;
  }
  chat_env.chat->header.previous_chain_length ^= 0x1;  // AD field tamper
  auto ack = server.DrainInbox("bob", drained.value().front().inbox_id);
  if (!AssertTrue(ack.ok(), "ack captured chat message")) {
    return false;
  }
  if (!AssertTrue(server.EnqueueEnvelope("bob", std::move(chat_env)).ok(),
                  "enqueue tampered chat envelope")) {
    return false;
  }

  auto result = bob_client.ProcessInbox(&server);
  return AssertTrue(!result.ok() && Contains(result.error(), "chat decrypt failed"),
                    "tampered chat AD rejected");
}

bool TestRatchetInteroperability() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;
  const std::string alice_user = "alice-ratchet";
  const std::string bob_user = "bob-ratchet";
  auto alice = Client::Create(alice_user);
  auto bob = Client::Create(bob_user);
  if (!AssertTrue(alice.ok() && bob.ok(), "alice/bob create ratchet")) {
    return false;
  }
  auto alice_client = alice.take_value();
  auto bob_client = bob.take_value();

  if (!AssertTrue(alice_client.PublishPrekeys(&server).ok(), "alice publish ratchet")) {
    return false;
  }
  if (!AssertTrue(bob_client.PublishPrekeys(&server).ok(), "bob publish ratchet")) {
    return false;
  }
  auto init_unverified = alice_client.InitiateSession(&server, bob_user, "hello");
  if (!AssertTrue(!init_unverified.ok(), "ratchet initiate blocked before verify")) {
    return false;
  }
  auto bob_safety = alice_client.GetPeerSafetyNumber(bob_user);
  if (!AssertTrue(bob_safety.ok(), "alice reads bob safety ratchet")) {
    return false;
  }
  if (!AssertTrue(alice_client.VerifyPeerSafetyNumber(bob_user, bob_safety.value()).ok(),
                  "alice verifies bob safety ratchet")) {
    return false;
  }
  if (!AssertTrue(alice_client.InitiateSession(&server, bob_user, "hello").ok(),
                  "initiate ratchet")) {
    return false;
  }
  auto bob_init_unverified = bob_client.ProcessInbox(&server);
  if (!AssertTrue(!bob_init_unverified.ok(), "bob blocks unverified alice ratchet")) {
    return false;
  }
  auto alice_safety = bob_client.GetPeerSafetyNumber(alice_user);
  if (!AssertTrue(alice_safety.ok(), "bob reads alice safety ratchet")) {
    return false;
  }
  if (!AssertTrue(bob_client.VerifyPeerSafetyNumber(alice_user, alice_safety.value()).ok(),
                  "bob verifies alice safety ratchet")) {
    return false;
  }
  auto bob_init = bob_client.ProcessInbox(&server);
  if (!AssertTrue(bob_init.ok() && bob_init.value().size() == 1, "bob receives init")) {
    return false;
  }

  for (int i = 0; i < 25; ++i) {
    if (!AssertTrue(alice_client.SendMessage(&server, bob_user, "a-" + std::to_string(i)).ok(),
                    "alice send ratchet sequence")) {
      return false;
    }
  }
  auto bob_msgs = bob_client.ProcessInbox(&server);
  if (!AssertTrue(bob_msgs.ok() && bob_msgs.value().size() == 25 &&
                      bob_msgs.value().front() == "a-0" &&
                      bob_msgs.value().back() == "a-24",
                  "bob receives ratcheted sequence")) {
    return false;
  }

  for (int i = 0; i < 25; ++i) {
    if (!AssertTrue(bob_client.SendMessage(&server, alice_user, "b-" + std::to_string(i)).ok(),
                    "bob send ratchet sequence")) {
      return false;
    }
  }
  auto alice_msgs = alice_client.ProcessInbox(&server);
  return AssertTrue(alice_msgs.ok() && alice_msgs.value().size() == 25 &&
                        alice_msgs.value().front() == "b-0" &&
                        alice_msgs.value().back() == "b-24",
                    "alice receives ratcheted sequence");
}

}  // namespace

int main() {
  char state_dir_template[] = "/tmp/pqchat_design_state_XXXXXX";
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
  if (setenv("PQCHAT_STATE_PASSPHRASE", "design-test-passphrase", 1) != 0) {
    std::cerr << "FAIL: setenv PQCHAT_STATE_PASSPHRASE\n";
    std::filesystem::remove_all(state_dir_template);
    return 1;
  }

  bool ok = true;
  ok &= TestCryptoUnitsFromDesign();
  ok &= TestTamperedChatHeaderAssociatedDataRejected();
  ok &= TestRatchetInteroperability();
  unsetenv("PQCHAT_STATE_DIR");
  unsetenv("PQCHAT_STATE_PASSPHRASE");
  std::filesystem::remove_all(state_dir_template);
  if (!ok) {
    return 1;
  }
  std::cout << "PASS: design coverage test suite\n";
  return 0;
}
