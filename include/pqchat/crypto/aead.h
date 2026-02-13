#pragma once

#include <cstdint>
#include <vector>

#include "pqchat/util/result.h"

namespace pqchat::crypto {

class AeadChaCha20Poly1305 {
 public:
  static constexpr size_t kKeySize = 32;
  static constexpr size_t kNonceSize = 12;
  static constexpr size_t kTagSize = 16;

  static Result<std::vector<uint8_t>> Seal(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce,
                                           const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& ad);

  static Result<std::vector<uint8_t>> Open(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce,
                                           const std::vector<uint8_t>& ciphertext,
                                           const std::vector<uint8_t>& ad);
};

std::vector<uint8_t> NonceFromCounter(uint64_t counter);

}  // namespace pqchat::crypto
