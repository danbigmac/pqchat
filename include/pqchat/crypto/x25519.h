#pragma once

#include <cstdint>
#include <vector>

#include "pqchat/crypto/secure_buffer.h"
#include "pqchat/util/result.h"

namespace pqchat::crypto {

struct X25519KeyPair {
  SecureBuffer private_key;
  std::vector<uint8_t> public_key;
};

class X25519 {
 public:
  static Result<X25519KeyPair> GenerateKeyPair();

  static Result<std::vector<uint8_t>> SharedSecret(
      const SecureBuffer& private_key,
      const std::vector<uint8_t>& peer_public_key);
};

}  // namespace pqchat::crypto
