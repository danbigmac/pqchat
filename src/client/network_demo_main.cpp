#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "pqchat/client/client.h"
#include "pqchat/client/tcp_server_api.h"

namespace {

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " [--host <host>] [--port <port>] [--tls-ca <pem>] "
               "[--tls-server-name <name>] [--tls-client-cert <pem>] "
               "[--tls-client-key <pem>] [--tls-pin-sha256 <hex>] "
               "[--register-token <token>] [--allow-insecure-dev]\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string host = "127.0.0.1";
  uint16_t port = 8080;
  std::string tls_ca;
  std::string tls_server_name;
  std::string tls_client_cert;
  std::string tls_client_key;
  std::vector<std::string> tls_pins;
  std::string registration_token;
  bool allow_insecure_dev = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--host") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      host = argv[++i];
      continue;
    }
    if (arg == "--port") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      int value = std::atoi(argv[++i]);
      if (value <= 0 || value > 65535) {
        std::cerr << "invalid port\n";
        return 1;
      }
      port = static_cast<uint16_t>(value);
      continue;
    }
    if (arg == "--tls-ca") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_ca = argv[++i];
      continue;
    }
    if (arg == "--tls-server-name") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_server_name = argv[++i];
      continue;
    }
    if (arg == "--tls-client-cert") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_client_cert = argv[++i];
      continue;
    }
    if (arg == "--tls-client-key") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_client_key = argv[++i];
      continue;
    }
    if (arg == "--tls-pin-sha256") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_pins.push_back(argv[++i]);
      continue;
    }
    if (arg == "--register-token") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      registration_token = argv[++i];
      continue;
    }
    if (arg == "--allow-insecure-dev") {
      allow_insecure_dev = true;
      continue;
    }
    PrintUsage(argv[0]);
    return 1;
  }
  if ((tls_client_cert.empty() && !tls_client_key.empty()) ||
      (!tls_client_cert.empty() && tls_client_key.empty())) {
    std::cerr << "TLS client auth requires both --tls-client-cert and --tls-client-key\n";
    return 1;
  }

  pqchat::client::TlsClientConfig tls_config;
  tls_config.enabled = !tls_ca.empty() || !tls_server_name.empty() ||
                       !tls_client_cert.empty() || !tls_client_key.empty();
  if (!allow_insecure_dev && !tls_config.enabled) {
    std::cerr
        << "TLS is required by default; configure TLS or use --allow-insecure-dev for local testing\n";
    return 1;
  }
  tls_config.ca_file = tls_ca;
  tls_config.server_name = tls_server_name;
  tls_config.client_cert_file = tls_client_cert;
  tls_config.client_key_file = tls_client_key;
  tls_config.pinned_server_cert_sha256_hex = tls_pins;

  auto alice_result = pqchat::client::Client::Create("alice");
  auto bob_result = pqchat::client::Client::Create("bob");
  if (!alice_result.ok() || !bob_result.ok()) {
    std::cerr << "client creation failed\n";
    return 1;
  }

  auto alice = alice_result.take_value();
  auto bob = bob_result.take_value();

  pqchat::client::TcpServerApi alice_api(
      host,
      port,
      alice.user_id(),
      alice.transport_auth_public_key(),
      [&](const std::vector<uint8_t>& message) {
        return alice.SignTransportAuth(message);
      },
      registration_token,
      tls_config);

  pqchat::client::TcpServerApi bob_api(
      host,
      port,
      bob.user_id(),
      bob.transport_auth_public_key(),
      [&](const std::vector<uint8_t>& message) {
        return bob.SignTransportAuth(message);
      },
      registration_token,
      tls_config);

  auto publish_alice = alice.PublishPrekeys(&alice_api);
  auto publish_bob = bob.PublishPrekeys(&bob_api);
  if (!publish_alice.ok() || !publish_bob.ok()) {
    std::cerr << "publish failed\n";
    if (!publish_alice.ok()) {
      std::cerr << "alice: " << publish_alice.error() << "\n";
    }
    if (!publish_bob.ok()) {
      std::cerr << "bob: " << publish_bob.error() << "\n";
    }
    return 1;
  }

  auto init = alice.InitiateSession(&alice_api, "bob", "hello from alice over TCP");
  if (!init.ok()) {
    std::cerr << "init failed: " << init.error() << "\n";
    return 1;
  }

  auto bob_inbox = bob.ProcessInbox(&bob_api);
  if (!bob_inbox.ok()) {
    std::cerr << "bob inbox failed: " << bob_inbox.error() << "\n";
    return 1;
  }
  for (const auto& msg : bob_inbox.value()) {
    std::cout << "bob received: " << msg << "\n";
  }

  auto reply = bob.SendMessage(&bob_api, "alice", "hello from bob over TCP");
  if (!reply.ok()) {
    std::cerr << "bob send failed: " << reply.error() << "\n";
    return 1;
  }

  auto alice_inbox = alice.ProcessInbox(&alice_api);
  if (!alice_inbox.ok()) {
    std::cerr << "alice inbox failed: " << alice_inbox.error() << "\n";
    return 1;
  }
  for (const auto& msg : alice_inbox.value()) {
    std::cout << "alice received: " << msg << "\n";
  }

  return 0;
}
