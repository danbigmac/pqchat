#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <atomic>
#include <mutex>
#include <deque>
#include <unordered_map>

#include <openssl/ssl.h>

#include "pqchat/server/server_api.h"
#include "pqchat/util/result.h"

namespace pqchat::server {

struct TlsServerConfig {
  bool enabled = false;
  std::string cert_file;
  std::string key_file;
  std::string client_ca_file;
  bool require_client_cert = false;
};

struct PreAuthRateLimitConfig {
  uint64_t window_seconds = 60;
  size_t register_per_addr = 20;
  size_t register_per_addr_user = 10;
  size_t auth_begin_per_addr = 60;
  size_t auth_begin_per_addr_user = 30;
  size_t auth_finish_per_addr = 60;
  size_t auth_finish_per_addr_user = 30;
  size_t register_global = 200;
  size_t auth_begin_global = 800;
  size_t auth_finish_global = 800;
};

class TcpServer {
 public:
  TcpServer(IServerApi* api,
            uint16_t port,
            TlsServerConfig tls_config = {},
            PreAuthRateLimitConfig preauth_rate_limit_config = {},
            size_t max_active_connections = 128,
            int client_io_timeout_seconds = 15);

  // Blocking accept loop. Stop with process signal.
 Result<void> Run();
  [[nodiscard]] size_t accepted_connections() const {
    return accepted_connections_.load(std::memory_order_relaxed);
  }

 private:
  Result<void> HandleConnection(int fd, SSL* tls, const std::string& peer_addr);
  Result<void> EnforcePreAuthRateLimit(uint32_t command, const std::string& peer_addr);
  Result<void> EnforcePreAuthUserRateLimit(uint32_t command,
                                           const std::string& peer_addr,
                                           const std::string& user_id);
  static uint64_t NowUnix();

  IServerApi* api_;
  uint16_t port_;
  TlsServerConfig tls_config_;
  PreAuthRateLimitConfig preauth_rate_limit_config_;
  size_t max_active_connections_;
  int client_io_timeout_seconds_;
  std::atomic<size_t> active_connections_{0};
  std::atomic<size_t> accepted_connections_{0};
  std::mutex preauth_rate_mu_;
  std::unordered_map<std::string, std::deque<uint64_t>> preauth_register_by_addr_;
  std::unordered_map<std::string, std::deque<uint64_t>> preauth_register_by_addr_user_;
  std::unordered_map<std::string, std::deque<uint64_t>> preauth_auth_begin_by_addr_;
  std::unordered_map<std::string, std::deque<uint64_t>> preauth_auth_begin_by_addr_user_;
  std::unordered_map<std::string, std::deque<uint64_t>> preauth_auth_finish_by_addr_;
  std::unordered_map<std::string, std::deque<uint64_t>> preauth_auth_finish_by_addr_user_;
  std::deque<uint64_t> preauth_register_global_;
  std::deque<uint64_t> preauth_auth_begin_global_;
  std::deque<uint64_t> preauth_auth_finish_global_;
};

}  // namespace pqchat::server
