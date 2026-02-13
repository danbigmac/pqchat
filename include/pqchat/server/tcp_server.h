#pragma once

#include <cstdint>
#include <string>

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

class TcpServer {
 public:
  TcpServer(IServerApi* api, uint16_t port, TlsServerConfig tls_config = {});

  // Blocking accept loop. Stop with process signal.
  Result<void> Run();

 private:
  Result<void> HandleConnection(int fd, SSL* tls);

  IServerApi* api_;
  uint16_t port_;
  TlsServerConfig tls_config_;
};

}  // namespace pqchat::server
