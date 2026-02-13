#pragma once

#include <cstdint>
#include <vector>

#include "pqchat/crypto/secure_buffer.h"
#include "pqchat/util/result.h"

namespace pqchat::crypto {

struct Ed25519KeyPair {
  SecureBuffer private_key;
  std::vector<uint8_t> public_key;
};

class Ed25519 {
 public:
  static Result<Ed25519KeyPair> GenerateKeyPair();

  static Result<std::vector<uint8_t>> Sign(const SecureBuffer& private_key,
                                           const std::vector<uint8_t>& message);

  static Result<void> Verify(const std::vector<uint8_t>& public_key,
                             const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& signature);
};

}  // namespace pqchat::crypto
