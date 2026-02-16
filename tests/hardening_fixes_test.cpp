#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

#include "pqchat/client/client.h"
#include "pqchat/client/tcp_server_api.h"
#include "pqchat/client/tls_pinning.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/protocol/serialization.h"
#include "pqchat/server/in_memory_server.h"
#include "pqchat/server/tcp_server.h"
#include "pqchat/server/tcp_wire.h"

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

std::string HexEncodeWithColons(const std::vector<uint8_t>& bytes) {
  std::string out;
  out.reserve(bytes.size() * 3);
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      out.push_back(':');
    }
    const std::vector<uint8_t> one = {bytes[i]};
    out += HexEncode(one);
  }
  return out;
}

pqchat::Result<std::vector<uint8_t>> BuildRegisterProof(
    const std::string& user_id,
    const pqchat::crypto::MlDsa65KeyPair& keypair) {
  auto sign_input = pqchat::protocol::BuildTransportRegisterSignInput(
      user_id, keypair.public_key);
  return pqchat::crypto::MlDsa65::Sign(keypair.private_key.get(), sign_input);
}

class ScopedEnvVar {
 public:
  ScopedEnvVar(const char* name, const std::string& value) : name_(name) {
    const char* prior = std::getenv(name_);
    if (prior != nullptr) {
      old_value_ = std::string(prior);
      had_old_value_ = true;
    }
    setenv(name_, value.c_str(), 1);
  }

  ~ScopedEnvVar() {
    if (had_old_value_) {
      setenv(name_, old_value_.c_str(), 1);
    } else {
      unsetenv(name_);
    }
  }

 private:
  const char* name_;
  bool had_old_value_ = false;
  std::string old_value_;
};

int ConnectLocalhost(uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

std::optional<uint16_t> ReserveEphemeralPort() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return std::nullopt;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return std::nullopt;
  }

  sockaddr_in bound{};
  socklen_t len = sizeof(bound);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
    close(fd);
    return std::nullopt;
  }
  const uint16_t port = ntohs(bound.sin_port);
  close(fd);
  return port;
}

pqchat::Result<uint16_t> StartTcpServerWithRateLimit(
    const pqchat::server::PreAuthRateLimitConfig& config) {
  auto port = ReserveEphemeralPort();
  if (!port.has_value()) {
    return pqchat::Result<uint16_t>::Err("failed to reserve ephemeral port");
  }

  // Intentionally leaked in test process lifetime because TcpServer::Run has no stop API.
  auto* backend = new pqchat::server::InMemoryServer();
  auto* server = new pqchat::server::TcpServer(backend, *port, {}, config, 128, 5);
  std::thread([server]() {
    auto run = server->Run();
    if (!run.ok()) {
      std::cerr << "background TcpServer exited: " << run.error() << "\n";
    }
  }).detach();

  for (int i = 0; i < 200; ++i) {
    int fd = ConnectLocalhost(*port);
    if (fd >= 0) {
      close(fd);
      return pqchat::Result<uint16_t>::Ok(*port);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return pqchat::Result<uint16_t>::Err("timed out waiting for TcpServer startup");
}

pqchat::Result<std::pair<uint32_t, std::string>> SendRegisterRequest(
    uint16_t port,
    uint32_t command,
    const std::vector<uint8_t>& payload) {
  int fd = ConnectLocalhost(port);
  if (fd < 0) {
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err("tcp connect failed");
  }

  auto write = pqchat::server::WriteFrame(fd, command, payload);
  if (!write.ok()) {
    close(fd);
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err(write.error());
  }

  auto response = pqchat::server::ReadFrame(fd);
  close(fd);
  if (!response.ok()) {
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err(response.error());
  }

  std::string message;
  if (response.value().first == static_cast<uint32_t>(pqchat::server::TcpStatus::kError)) {
    auto decoded = pqchat::protocol::DeserializeString(response.value().second);
    message = decoded.ok() ? decoded.value() : "server returned malformed error payload";
  }
  return pqchat::Result<std::pair<uint32_t, std::string>>::Ok(
      {response.value().first, message});
}

pqchat::Result<std::pair<uint32_t, std::string>> SendRegisterRequest(
    uint16_t port,
    const std::string& user_id,
    const pqchat::crypto::MlDsa65KeyPair& auth_key) {
  pqchat::protocol::RegisterRequest request;
  request.user_id = user_id;
  request.transport_auth_public_key = auth_key.public_key;
  auto proof = BuildRegisterProof(user_id, auth_key);
  if (!proof.ok()) {
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err(proof.error());
  }
  request.proof_signature_mldsa65 = proof.take_value();
  auto payload = pqchat::protocol::SerializeRegisterRequest(request);
  if (!payload.ok()) {
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err(payload.error());
  }
  return SendRegisterRequest(port,
                             static_cast<uint32_t>(
                                 pqchat::server::TcpCommand::kRegisterTransportIdentity),
                             payload.value());
}

pqchat::Result<std::pair<uint32_t, std::string>> SendAuthBeginRequest(uint16_t port,
                                                                       const std::string& user_id,
                                                                       uint8_t nonce_byte) {
  pqchat::protocol::AuthBeginRequest request;
  request.user_id = user_id;
  request.client_nonce = std::vector<uint8_t>(32, nonce_byte);
  auto payload = pqchat::protocol::SerializeAuthBeginRequest(request);
  if (!payload.ok()) {
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err(payload.error());
  }
  return SendRegisterRequest(port,
                             static_cast<uint32_t>(pqchat::server::TcpCommand::kAuthBegin),
                             payload.value());
}

pqchat::Result<std::pair<uint32_t, std::string>> SendAuthFinishRequest(
    uint16_t port,
    const std::string& user_id,
    int suffix) {
  pqchat::protocol::AuthFinishRequest request;
  request.user_id = user_id;
  std::vector<uint8_t> challenge_seed(16, 0);
  challenge_seed[0] = static_cast<uint8_t>(suffix & 0xFF);
  challenge_seed[1] = static_cast<uint8_t>((suffix >> 8) & 0xFF);
  request.challenge_id = HexEncode(challenge_seed);
  request.client_nonce = std::vector<uint8_t>(32, 0x11);
  request.server_nonce = std::vector<uint8_t>(32, 0x22);
  request.expires_at_unix = 1;
  request.signature_mldsa65 = std::vector<uint8_t>(128, 0xAA);
  auto payload = pqchat::protocol::SerializeAuthFinishRequest(request);
  if (!payload.ok()) {
    return pqchat::Result<std::pair<uint32_t, std::string>>::Err(payload.error());
  }
  return SendRegisterRequest(port,
                             static_cast<uint32_t>(pqchat::server::TcpCommand::kAuthFinish),
                             payload.value());
}

bool TestTcpServerPreAuthRateLimits() {
  using pqchat::crypto::MlDsa65;
  using pqchat::server::PreAuthRateLimitConfig;
  using pqchat::server::TcpStatus;

  auto key = MlDsa65::GenerateKeyPair();
  if (!AssertTrue(key.ok(), "ML-DSA keygen for tcp rate-limit test")) {
    return false;
  }

  PreAuthRateLimitConfig per_addr_config;
  per_addr_config.window_seconds = 300;
  per_addr_config.register_per_addr = 2;
  per_addr_config.register_global = 100;
  per_addr_config.auth_begin_per_addr = 100;
  per_addr_config.auth_begin_global = 1000;
  per_addr_config.auth_finish_per_addr = 100;
  per_addr_config.auth_finish_global = 1000;
  auto per_addr_server = StartTcpServerWithRateLimit(per_addr_config);
  if (!AssertTrue(per_addr_server.ok(), "start tcp server for per-address limiting")) {
    return false;
  }

  for (int i = 0; i < 2; ++i) {
    auto response = SendRegisterRequest(per_addr_server.value(),
                                        "per-addr-user-" + std::to_string(i),
                                        key.value());
    if (!AssertTrue(response.ok(), "send per-address register request")) {
      return false;
    }
    if (!AssertTrue(response.value().first == static_cast<uint32_t>(TcpStatus::kOk),
                    "per-address requests below limit succeed")) {
      return false;
    }
  }
  auto per_addr_limited = SendRegisterRequest(per_addr_server.value(),
                                              "per-addr-user-limited",
                                              key.value());
  if (!AssertTrue(per_addr_limited.ok(), "send per-address limit-breach request")) {
    return false;
  }
  if (!AssertTrue(per_addr_limited.value().first ==
                      static_cast<uint32_t>(TcpStatus::kError) &&
                      Contains(per_addr_limited.value().second, "source address"),
                  "tcp server enforces per-address pre-auth limit")) {
    return false;
  }

  PreAuthRateLimitConfig global_config = per_addr_config;
  global_config.register_per_addr = 100;
  global_config.register_global = 2;
  auto global_server = StartTcpServerWithRateLimit(global_config);
  if (!AssertTrue(global_server.ok(), "start tcp server for global limiting")) {
    return false;
  }

  for (int i = 0; i < 2; ++i) {
    auto response = SendRegisterRequest(global_server.value(),
                                        "global-user-" + std::to_string(i),
                                        key.value());
    if (!AssertTrue(response.ok(), "send global register request")) {
      return false;
    }
    if (!AssertTrue(response.value().first == static_cast<uint32_t>(TcpStatus::kOk),
                    "global requests below limit succeed")) {
      return false;
    }
  }
  auto global_limited = SendRegisterRequest(global_server.value(),
                                            "global-user-limited",
                                            key.value());
  if (!AssertTrue(global_limited.ok() &&
                      global_limited.value().first ==
                          static_cast<uint32_t>(TcpStatus::kError) &&
                      Contains(global_limited.value().second, "global"),
                  "tcp server enforces global pre-auth limit")) {
    return false;
  }

  PreAuthRateLimitConfig source_user_config = per_addr_config;
  source_user_config.register_per_addr = 100;
  source_user_config.register_global = 1000;
  source_user_config.register_per_addr_user = 2;
  auto source_user_server = StartTcpServerWithRateLimit(source_user_config);
  if (!AssertTrue(source_user_server.ok(),
                  "start tcp server for source+user limiting")) {
    return false;
  }
  for (int i = 0; i < 2; ++i) {
    auto response = SendRegisterRequest(source_user_server.value(),
                                        "same-user",
                                        key.value());
    if (!AssertTrue(response.ok(), "send source+user register request")) {
      return false;
    }
    if (!AssertTrue(response.value().first == static_cast<uint32_t>(TcpStatus::kOk),
                    "source+user requests below limit succeed")) {
      return false;
    }
  }
  auto source_user_limited = SendRegisterRequest(source_user_server.value(),
                                                 "same-user",
                                                 key.value());
  if (!AssertTrue(source_user_limited.ok() &&
                      source_user_limited.value().first ==
                          static_cast<uint32_t>(TcpStatus::kError) &&
                      Contains(source_user_limited.value().second, "source+user"),
                  "tcp server enforces source+user pre-auth limit")) {
    return false;
  }

  PreAuthRateLimitConfig begin_config = per_addr_config;
  begin_config.auth_begin_per_addr = 2;
  begin_config.auth_begin_global = 100;
  auto begin_server = StartTcpServerWithRateLimit(begin_config);
  if (!AssertTrue(begin_server.ok(), "start tcp server for auth-begin limiting")) {
    return false;
  }
  for (int i = 0; i < 2; ++i) {
    auto response = SendAuthBeginRequest(begin_server.value(), "unknown-user", 0x41 + i);
    if (!AssertTrue(response.ok(), "send auth-begin request under limit")) {
      return false;
    }
    if (!AssertTrue(response.value().first == static_cast<uint32_t>(TcpStatus::kError) &&
                        !Contains(response.value().second, "rate limit"),
                    "auth-begin under limit reaches backend")) {
      return false;
    }
  }
  auto begin_limited = SendAuthBeginRequest(begin_server.value(), "unknown-user", 0x7F);
  if (!AssertTrue(begin_limited.ok() &&
                      begin_limited.value().first ==
                          static_cast<uint32_t>(TcpStatus::kError) &&
                      Contains(begin_limited.value().second, "auth begin rate limit"),
                  "tcp server enforces auth-begin pre-auth limit")) {
    return false;
  }

  PreAuthRateLimitConfig finish_config = per_addr_config;
  finish_config.auth_finish_per_addr = 2;
  finish_config.auth_finish_global = 100;
  auto finish_server = StartTcpServerWithRateLimit(finish_config);
  if (!AssertTrue(finish_server.ok(), "start tcp server for auth-finish limiting")) {
    return false;
  }
  for (int i = 0; i < 2; ++i) {
    auto response = SendAuthFinishRequest(finish_server.value(), "unknown-user", i);
    if (!AssertTrue(response.ok(), "send auth-finish request under limit")) {
      return false;
    }
    if (!AssertTrue(response.value().first == static_cast<uint32_t>(TcpStatus::kError) &&
                        !Contains(response.value().second, "rate limit"),
                    "auth-finish under limit reaches backend")) {
      return false;
    }
  }
  auto finish_limited = SendAuthFinishRequest(finish_server.value(), "unknown-user", 999);
  return AssertTrue(finish_limited.ok() &&
                        finish_limited.value().first ==
                            static_cast<uint32_t>(TcpStatus::kError) &&
                        Contains(finish_limited.value().second, "auth finish rate limit"),
                    "tcp server enforces auth-finish pre-auth limit");
}

bool TestTcpServerApiConnectionReuse() {
  using pqchat::client::Client;
  using pqchat::client::TcpServerApi;
  using pqchat::server::InMemoryServer;
  using pqchat::server::TcpServer;

  auto port = ReserveEphemeralPort();
  if (!AssertTrue(port.has_value(), "reserve ephemeral port for connection reuse test")) {
    return false;
  }

  auto* backend = new InMemoryServer();
  auto* server = new TcpServer(backend, *port, {}, {}, 128, 5);
  std::thread([server]() {
    auto run = server->Run();
    if (!run.ok()) {
      std::cerr << "background TcpServer exited: " << run.error() << "\n";
    }
  }).detach();

  bool started = false;
  for (int i = 0; i < 200; ++i) {
    int fd = ConnectLocalhost(*port);
    if (fd >= 0) {
      close(fd);
      started = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (!AssertTrue(started, "wait for server startup in connection reuse test")) {
    return false;
  }
  for (int i = 0; i < 200 && server->accepted_connections() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  const size_t baseline_accepts = server->accepted_connections();

  char dir_template[] = "/tmp/pqchat_reuse_state_test_XXXXXX";
  int state_fd = mkstemp(dir_template);
  if (!AssertTrue(state_fd >= 0, "mkstemp for connection reuse state dir")) {
    return false;
  }
  close(state_fd);
  unlink(dir_template);
  if (!AssertTrue(mkdir(dir_template, 0700) == 0, "mkdir for connection reuse state dir")) {
    return false;
  }
  const std::string state_dir(dir_template);
  ScopedEnvVar state_env("PQCHAT_STATE_DIR", state_dir);
  ScopedEnvVar pass_env("PQCHAT_STATE_PASSPHRASE", "reuse-test-passphrase");

  auto client_result = Client::Create("reuse-user");
  if (!AssertTrue(client_result.ok(), "create client for connection reuse test")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto client = client_result.take_value();

  TcpServerApi api("127.0.0.1",
                   *port,
                   client.user_id(),
                   client.transport_auth_public_key(),
                   [&](const std::vector<uint8_t>& message) {
                     return client.SignTransportAuth(message);
                   });

  if (!AssertTrue(client.PublishPrekeys(&api).ok(), "publish prekeys over pooled connection")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto bundle = api.AcquireBundleForSession("reuse-user");
  if (!AssertTrue(bundle.ok(), "acquire bundle over pooled connection")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto drain = api.DrainInbox("reuse-user");
  if (!AssertTrue(drain.ok(), "drain inbox over pooled connection")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  pqchat::protocol::InitialMessage forged_initial;
  forged_initial.session_id = "forged-session";
  forged_initial.from_user = "reuse-user";
  forged_initial.to_user = "other-recipient";
  forged_initial.version = pqchat::protocol::kProtocolVersion;
  forged_initial.cipher_suite = pqchat::protocol::kCipherSuite;
  auto forged_enqueue = api.EnqueueEnvelope("different-target",
                                            pqchat::protocol::Envelope::FromInitial(forged_initial));
  if (!AssertTrue(!forged_enqueue.ok() &&
                      Contains(forged_enqueue.error(), "recipient mismatch"),
                  "server enforces envelope recipient binding")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }

  if (!AssertTrue(api.LogoutCurrentSession().ok(), "logout current session")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto bundle_after_logout = api.AcquireBundleForSession("reuse-user");
  if (!AssertTrue(bundle_after_logout.ok(), "reauth after logout succeeds")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }

  const size_t accepts_after = server->accepted_connections();
  std::filesystem::remove_all(state_dir);
  if (accepts_after != baseline_accepts + 2) {
    std::cerr << "observed accepts: baseline=" << baseline_accepts
              << " after=" << accepts_after << "\n";
    return AssertTrue(false,
                      "TcpServerApi reuses one connection and reconnects cleanly after logout");
  }
  return true;
}

bool TestClientStatePersistenceAcrossRestart() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  char dir_template[] = "/tmp/pqchat_client_state_test_XXXXXX";
  int state_fd = mkstemp(dir_template);
  if (!AssertTrue(state_fd >= 0, "mkstemp for client state test")) {
    return false;
  }
  close(state_fd);
  unlink(dir_template);
  if (!AssertTrue(mkdir(dir_template, 0700) == 0, "mkdir for client state test")) {
    return false;
  }
  const std::string state_dir(dir_template);
  ScopedEnvVar state_env("PQCHAT_STATE_DIR", state_dir);
  ScopedEnvVar state_passphrase_env("PQCHAT_STATE_PASSPHRASE",
                                    "hardening-persistence-passphrase");

  InMemoryServer server;
  auto alice = Client::Create("alice-persist-test");
  auto bob = Client::Create("bob-persist-test");
  if (!AssertTrue(alice.ok() && bob.ok(), "create clients for persistence test")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }

  auto alice_client = alice.take_value();
  auto bob_client = bob.take_value();
  if (!AssertTrue(alice_client.PublishPrekeys(&server).ok(), "publish alice prekeys")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  if (!AssertTrue(bob_client.PublishPrekeys(&server).ok(), "publish bob prekeys")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto init_unverified =
      alice_client.InitiateSession(&server, "bob-persist-test", "hello");
  if (!AssertTrue(!init_unverified.ok(), "initiate blocked before verify")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto bob_safety = alice_client.GetPeerSafetyNumber("bob-persist-test");
  if (!AssertTrue(bob_safety.ok(), "alice reads bob safety")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  if (!AssertTrue(
          alice_client.VerifyPeerSafetyNumber("bob-persist-test", bob_safety.value()).ok(),
          "alice verifies bob safety")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  if (!AssertTrue(alice_client.InitiateSession(&server, "bob-persist-test", "hello").ok(),
                  "initiate session for persistence test")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto bob_init_unverified = bob_client.ProcessInbox(&server);
  if (!AssertTrue(!bob_init_unverified.ok(), "bob blocks unverified alice")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto alice_safety = bob_client.GetPeerSafetyNumber("alice-persist-test");
  if (!AssertTrue(alice_safety.ok(), "bob reads alice safety")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  if (!AssertTrue(
          bob_client.VerifyPeerSafetyNumber("alice-persist-test", alice_safety.value()).ok(),
          "bob verifies alice safety")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto bob_init = bob_client.ProcessInbox(&server);
  if (!AssertTrue(bob_init.ok() && bob_init.value().size() == 1 &&
                      bob_init.value().front() == "hello",
                  "bob receives initial handshake payload")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }

  if (!AssertTrue(alice_client.SendMessage(&server, "bob-persist-test", "after-restart").ok(),
                  "alice send before bob restart")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }

  auto bob_restored = Client::Create("bob-persist-test");
  if (!AssertTrue(bob_restored.ok(), "reload bob state from disk")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto restored_inbox = bob_restored.value().ProcessInbox(&server);
  if (!AssertTrue(restored_inbox.ok() && restored_inbox.value().size() == 1 &&
                      restored_inbox.value().front() == "after-restart",
                  "restored bob decrypts pending session message")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }

  auto bob_restored_client = bob_restored.take_value();
  if (!AssertTrue(bob_restored_client.SendMessage(&server,
                                                  "alice-persist-test",
                                                  "reply-after-restart").ok(),
                  "restored bob can continue ratchet send")) {
    std::filesystem::remove_all(state_dir);
    return false;
  }
  auto alice_inbox = alice_client.ProcessInbox(&server);
  const bool ok = AssertTrue(alice_inbox.ok() && alice_inbox.value().size() == 1 &&
                                 alice_inbox.value().front() == "reply-after-restart",
                             "alice decrypts reply from restored bob");
  std::filesystem::remove_all(state_dir);
  return ok;
}

bool TestTlsPinParsingAndRotation() {
  using pqchat::client::ParseSha256PinHex;
  using pqchat::client::VerifyPinnedSha256Fingerprint;

  std::vector<uint8_t> fingerprint(32, 0);
  for (size_t i = 0; i < fingerprint.size(); ++i) {
    fingerprint[i] = static_cast<uint8_t>(i);
  }

  const std::string good_pin = HexEncode(fingerprint);
  auto parsed_good = ParseSha256PinHex(good_pin);
  if (!AssertTrue(parsed_good.ok() && parsed_good.value() == fingerprint,
                  "parse plain hex SHA-256 pin")) {
    return false;
  }

  auto parsed_colon = ParseSha256PinHex(HexEncodeWithColons(fingerprint));
  if (!AssertTrue(parsed_colon.ok() && parsed_colon.value() == fingerprint,
                  "parse colon-separated SHA-256 pin")) {
    return false;
  }

  auto no_pins = VerifyPinnedSha256Fingerprint(fingerprint, {});
  if (!AssertTrue(no_pins.ok(), "empty pin list allowed")) {
    return false;
  }

  std::vector<uint8_t> other_fp = fingerprint;
  other_fp[0] ^= 0x5A;
  const std::string other_pin = HexEncode(other_fp);
  auto rotated = VerifyPinnedSha256Fingerprint(fingerprint, {other_pin, good_pin});
  if (!AssertTrue(rotated.ok(), "pin rotation accepts any configured matching pin")) {
    return false;
  }

  auto mismatch = VerifyPinnedSha256Fingerprint(fingerprint, {other_pin});
  if (!AssertTrue(!mismatch.ok() && Contains(mismatch.error(), "mismatch"),
                  "pin mismatch rejected")) {
    return false;
  }

  auto bad_parse = ParseSha256PinHex("not-a-pin");
  if (!AssertTrue(!bad_parse.ok(), "invalid pin text rejected")) {
    return false;
  }

  auto bad_config = VerifyPinnedSha256Fingerprint(fingerprint, {"0011"});
  return AssertTrue(!bad_config.ok() && Contains(bad_config.error(), "invalid configured TLS pin"),
                    "invalid configured pin causes explicit error");
}

}  // namespace

int main() {
  bool ok = true;
  ok &= TestTcpServerPreAuthRateLimits();
  ok &= TestTcpServerApiConnectionReuse();
  ok &= TestClientStatePersistenceAcrossRestart();
  ok &= TestTlsPinParsingAndRotation();
  if (!ok) {
    return 1;
  }
  std::cout << "PASS: hardening fixes test suite\n";
  return 0;
}
