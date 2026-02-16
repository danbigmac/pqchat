#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "pqchat/crypto/hkdf.h"
#include "pqchat/server/sqlite_store.h"
#include "pqchat/server/tcp_server.h"

namespace {

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " [--db <sqlite_path>] [--port <port>] [--tls-cert <pem>] "
               "[--tls-key <pem>] [--tls-client-ca <pem>] [--tls-require-client-cert] "
               "[--registration-token <token>] [--max-active-connections <n>] "
               "[--preauth-window-seconds <n>] [--preauth-register-per-addr <n>] "
               "[--preauth-auth-begin-per-addr <n>] [--preauth-auth-finish-per-addr <n>] "
               "[--preauth-register-global <n>] [--preauth-auth-begin-global <n>] "
               "[--preauth-auth-finish-global <n>] "
               "[--io-timeout-seconds <n>] [--allow-insecure-dev] "
               "[--derive-registration-token <user_id>]\n";
}

bool ParseStrictPositiveU64(const char* text, uint64_t* out) {
  if (text == nullptr || *text == '\0') {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  unsigned long long value = std::strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0) {
    return false;
  }
  *out = static_cast<uint64_t>(value);
  return true;
}

bool ParseStrictPositiveSize(const char* text, size_t* out) {
  uint64_t parsed = 0;
  if (!ParseStrictPositiveU64(text, &parsed)) {
    return false;
  }
  if (parsed > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
    return false;
  }
  *out = static_cast<size_t>(parsed);
  return true;
}

std::string HexEncode(const std::vector<uint8_t>& bytes) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : bytes) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

}  // namespace

int main(int argc, char** argv) {
  std::string db_path = "pqchat.db";
  uint16_t port = 8080;
  std::string tls_cert;
  std::string tls_key;
  std::string tls_client_ca;
  std::string registration_token;
  bool tls_require_client_cert = false;
  bool allow_insecure_dev = false;
  size_t max_active_connections = 128;
  int io_timeout_seconds = 15;
  std::string derive_registration_token_user;
  pqchat::server::PreAuthRateLimitConfig preauth_rate_limit_config;

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
    if (arg == "--registration-token") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      registration_token = argv[++i];
      continue;
    }
    if (arg == "--max-active-connections") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      int value = std::atoi(argv[++i]);
      if (value <= 0) {
        std::cerr << "invalid max active connections\n";
        return 1;
      }
      max_active_connections = static_cast<size_t>(value);
      continue;
    }
    if (arg == "--preauth-window-seconds") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      uint64_t value = 0;
      if (!ParseStrictPositiveU64(argv[++i], &value)) {
        std::cerr << "invalid preauth window seconds\n";
        return 1;
      }
      preauth_rate_limit_config.window_seconds = value;
      continue;
    }
    if (arg == "--preauth-register-per-addr") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      size_t value = 0;
      if (!ParseStrictPositiveSize(argv[++i], &value)) {
        std::cerr << "invalid preauth register-per-addr limit\n";
        return 1;
      }
      preauth_rate_limit_config.register_per_addr = value;
      continue;
    }
    if (arg == "--preauth-auth-begin-per-addr") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      size_t value = 0;
      if (!ParseStrictPositiveSize(argv[++i], &value)) {
        std::cerr << "invalid preauth auth-begin-per-addr limit\n";
        return 1;
      }
      preauth_rate_limit_config.auth_begin_per_addr = value;
      continue;
    }
    if (arg == "--preauth-auth-finish-per-addr") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      size_t value = 0;
      if (!ParseStrictPositiveSize(argv[++i], &value)) {
        std::cerr << "invalid preauth auth-finish-per-addr limit\n";
        return 1;
      }
      preauth_rate_limit_config.auth_finish_per_addr = value;
      continue;
    }
    if (arg == "--preauth-register-global") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      size_t value = 0;
      if (!ParseStrictPositiveSize(argv[++i], &value)) {
        std::cerr << "invalid preauth register-global limit\n";
        return 1;
      }
      preauth_rate_limit_config.register_global = value;
      continue;
    }
    if (arg == "--preauth-auth-begin-global") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      size_t value = 0;
      if (!ParseStrictPositiveSize(argv[++i], &value)) {
        std::cerr << "invalid preauth auth-begin-global limit\n";
        return 1;
      }
      preauth_rate_limit_config.auth_begin_global = value;
      continue;
    }
    if (arg == "--preauth-auth-finish-global") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      size_t value = 0;
      if (!ParseStrictPositiveSize(argv[++i], &value)) {
        std::cerr << "invalid preauth auth-finish-global limit\n";
        return 1;
      }
      preauth_rate_limit_config.auth_finish_global = value;
      continue;
    }
    if (arg == "--io-timeout-seconds") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      int value = std::atoi(argv[++i]);
      if (value <= 0) {
        std::cerr << "invalid io timeout seconds\n";
        return 1;
      }
      io_timeout_seconds = value;
      continue;
    }
    if (arg == "--allow-insecure-dev") {
      allow_insecure_dev = true;
      continue;
    }
    if (arg == "--derive-registration-token") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 1;
      }
      derive_registration_token_user = argv[++i];
      continue;
    }

    PrintUsage(argv[0]);
    return 1;
  }

  if (!derive_registration_token_user.empty()) {
    if (registration_token.empty()) {
      std::cerr << "--derive-registration-token requires --registration-token\n";
      return 1;
    }
    auto token = pqchat::crypto::HmacSha256(
        pqchat::crypto::ToBytes(registration_token),
        pqchat::crypto::ToBytes(derive_registration_token_user));
    if (!token.ok()) {
      std::cerr << "failed to derive registration token: " << token.error() << "\n";
      return 1;
    }
    std::cout << HexEncode(token.value()) << "\n";
    return 0;
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
  if (!allow_insecure_dev && !tls_enabled) {
    std::cerr
        << "TLS is required by default; configure TLS or use --allow-insecure-dev for local testing\n";
    return 1;
  }
  if (!allow_insecure_dev && registration_token.empty()) {
    std::cerr
        << "registration provisioning secret is required by default; provide --registration-token or use --allow-insecure-dev for local testing\n";
    return 1;
  }

  auto store = pqchat::server::SqliteStore::Open(db_path, registration_token);
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

  pqchat::server::TcpServer server(store.value().get(),
                                   port,
                                   std::move(tls_config),
                                   std::move(preauth_rate_limit_config),
                                   max_active_connections,
                                   io_timeout_seconds);
  auto run = server.Run();
  if (!run.ok()) {
    std::cerr << "server failed: " << run.error() << "\n";
    return 1;
  }

  return 0;
}
