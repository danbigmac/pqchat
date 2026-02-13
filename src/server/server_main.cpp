#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>

#include "pqchat/server/sqlite_store.h"
#include "pqchat/server/tcp_server.h"

namespace {

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " [--db <sqlite_path>] [--port <port>] [--tls-cert <pem>] "
               "[--tls-key <pem>] [--tls-client-ca <pem>] [--tls-require-client-cert]\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string db_path = "pqchat.db";
  uint16_t port = 8080;
  std::string tls_cert;
  std::string tls_key;
  std::string tls_client_ca;
  bool tls_require_client_cert = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--db") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      db_path = argv[++i];
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
    if (arg == "--tls-cert") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_cert = argv[++i];
      continue;
    }
    if (arg == "--tls-key") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_key = argv[++i];
      continue;
    }
    if (arg == "--tls-client-ca") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      tls_client_ca = argv[++i];
      continue;
    }
    if (arg == "--tls-require-client-cert") {
      tls_require_client_cert = true;
      continue;
    }

    PrintUsage(argv[0]);
    return 1;
  }

  bool tls_enabled = !tls_cert.empty() || !tls_key.empty() || !tls_client_ca.empty() ||
                     tls_require_client_cert;
  if (tls_enabled && (tls_cert.empty() || tls_key.empty())) {
    std::cerr << "TLS requires both --tls-cert and --tls-key\n";
    return 1;
  }
  if (tls_require_client_cert && tls_client_ca.empty()) {
    std::cerr << "--tls-require-client-cert requires --tls-client-ca\n";
    return 1;
  }

  auto store = pqchat::server::SqliteStore::Open(db_path);
  if (!store.ok()) {
    std::cerr << "failed to open sqlite store: " << store.error() << "\n";
    return 1;
  }

  pqchat::server::TlsServerConfig tls_config;
  tls_config.enabled = tls_enabled;
  tls_config.cert_file = tls_cert;
  tls_config.key_file = tls_key;
  tls_config.client_ca_file = tls_client_ca;
  tls_config.require_client_cert = tls_require_client_cert;

  std::cout << "pqchat_server listening on 0.0.0.0:" << port << " using db " << db_path
            << (tls_enabled ? " [TLS enabled]" : " [TLS disabled]") << "\n";

  pqchat::server::TcpServer server(store.value().get(), port, std::move(tls_config));
  auto run = server.Run();
  if (!run.ok()) {
    std::cerr << "server failed: " << run.error() << "\n";
    return 1;
  }

  return 0;
}
