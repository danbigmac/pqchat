#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include <openssl/ssl.h>

#include "pqchat/util/result.h"

namespace pqchat::server {

enum class TcpCommand : uint32_t {
  kPublishBundle = 1,
  kAcquireBundle = 2,
  kEnqueueEnvelope = 3,
  kDrainInbox = 4,
  kRegisterTransportIdentity = 5,
  kAuthBegin = 6,
  kAuthFinish = 7,
};

enum class TcpStatus : uint32_t {
  kOk = 0,
  kError = 1,
};

// Frame format: [u32 type][u32 payload_len][payload bytes]
Result<void> WriteFrame(int fd, uint32_t type, const std::vector<uint8_t>& payload);
Result<void> WriteFrameTls(SSL* ssl, uint32_t type, const std::vector<uint8_t>& payload);

// Returns Err("eof") when the peer cleanly closes before a new frame.
Result<std::pair<uint32_t, std::vector<uint8_t>>> ReadFrame(int fd);
Result<std::pair<uint32_t, std::vector<uint8_t>>> ReadFrameTls(SSL* ssl);

}  // namespace pqchat::server
