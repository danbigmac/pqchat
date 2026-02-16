#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "pqchat/client/client.h"
#include "pqchat/client/tcp_server_api.h"

namespace {

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " --user <user_id> [--host <host>] [--port <port>] [--publish-on-start] "
               "[--tls-ca <pem>] [--tls-server-name <name>] [--tls-client-cert <pem>] "
               "[--tls-client-key <pem>] [--tls-pin-sha256 <hex>] "
               "[--register-token <token>] [--allow-insecure-dev]\n";
}

std::string TrimLeadingSpace(std::string value) {
  size_t i = 0;
  while (i < value.size() && (value[i] == ' ' || value[i] == '\t')) {
    ++i;
  }
  return value.substr(i);
}

void PrintHelp() {
  std::cout
      << "Commands:\n"
      << "  publish\n"
      << "  init <peer> <message>\n"
      << "  send <peer> <message>\n"
      << "  poll\n"
      << "  safety <peer>\n"
      << "  verify <peer> <safety_number>\n"
      << "  help\n"
      << "  quit\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string user;
  std::string host = "127.0.0.1";
  uint16_t port = 8080;
  bool publish_on_start = false;
  std::string tls_ca;
  std::string tls_server_name;
  std::string tls_client_cert;
  std::string tls_client_key;
  std::vector<std::string> tls_pins;
  std::string registration_token;
  bool allow_insecure_dev = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--user") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      user = argv[++i];
      continue;
    }
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
    if (arg == "--publish-on-start") {
      publish_on_start = true;
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

  if (user.empty()) {
    PrintUsage(argv[0]);
    return 1;
  }
  if ((tls_client_cert.empty() && !tls_client_key.empty()) ||
      (!tls_client_cert.empty() && tls_client_key.empty())) {
    std::cerr << "TLS client auth requires both --tls-client-cert and --tls-client-key\n";
    return 1;
  }

  auto client_result = pqchat::client::Client::Create(user);
  if (!client_result.ok()) {
    std::cerr << "client init failed: " << client_result.error() << "\n";
    return 1;
  }

  auto client = client_result.take_value();
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
  tls_config.pinned_server_cert_sha256_hex = std::move(tls_pins);

  pqchat::client::TcpServerApi api(
      host,
      port,
      user,
      client.transport_auth_public_key(),
      [&](const std::vector<uint8_t>& message) {
        return client.SignTransportAuth(message);
      },
      registration_token,
      std::move(tls_config));

  if (publish_on_start) {
    auto publish = client.PublishPrekeys(&api);
    if (!publish.ok()) {
      std::cerr << "publish failed: " << publish.error() << "\n";
      return 1;
    }
    std::cout << "published prekeys\n";
  }

  std::cout << "pqchat client ready for user '" << user << "' on " << host << ':' << port
            << "\n";
  PrintHelp();

  std::string line;
  while (true) {
    std::cout << user << "> ";
    if (!std::getline(std::cin, line)) {
      break;
    }

    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    if (cmd.empty()) {
      continue;
    }

    if (cmd == "quit" || cmd == "exit") {
      break;
    }

    if (cmd == "help") {
      PrintHelp();
      continue;
    }

    if (cmd == "publish") {
      auto publish = client.PublishPrekeys(&api);
      if (!publish.ok()) {
        std::cout << "error: " << publish.error() << "\n";
      } else {
        std::cout << "ok\n";
      }
      continue;
    }

    if (cmd == "safety") {
      std::string peer;
      iss >> peer;
      if (peer.empty()) {
        std::cout << "error: missing peer\n";
        continue;
      }
      auto safety = client.GetPeerSafetyNumber(peer);
      if (!safety.ok()) {
        std::cout << "error: " << safety.error() << "\n";
      } else {
        std::cout << safety.value() << "\n";
      }
      continue;
    }

    if (cmd == "verify") {
      std::string peer;
      std::string safety;
      iss >> peer >> safety;
      if (peer.empty() || safety.empty()) {
        std::cout << "error: usage verify <peer> <safety_number>\n";
        continue;
      }
      auto status = client.VerifyPeerSafetyNumber(peer, safety);
      if (!status.ok()) {
        std::cout << "error: " << status.error() << "\n";
      } else {
        std::cout << "ok\n";
      }
      continue;
    }

    if (cmd == "poll") {
      auto inbox = client.ProcessInbox(&api);
      if (!inbox.ok()) {
        std::cout << "error: " << inbox.error() << "\n";
      } else if (inbox.value().empty()) {
        std::cout << "no messages\n";
      } else {
        for (const auto& msg : inbox.value()) {
          std::cout << "message: " << msg << "\n";
        }
      }
      continue;
    }

    if (cmd == "init" || cmd == "send") {
      std::string peer;
      iss >> peer;
      if (peer.empty()) {
        std::cout << "error: missing peer\n";
        continue;
      }

      std::string rest;
      std::getline(iss, rest);
      std::string msg = TrimLeadingSpace(rest);
      if (msg.empty()) {
        std::cout << "error: missing message\n";
        continue;
      }

      if (cmd == "init") {
        auto status = client.InitiateSession(&api, peer, msg);
        if (!status.ok()) {
          std::cout << "error: " << status.error() << "\n";
        } else {
          std::cout << "ok\n";
        }
      } else {
        auto status = client.SendMessage(&api, peer, msg);
        if (!status.ok()) {
          std::cout << "error: " << status.error() << "\n";
        } else {
          std::cout << "ok\n";
        }
      }
      continue;
    }

    std::cout << "error: unknown command\n";
  }

  return 0;
}
