#pragma once

#include <cstdint>
#include <vector>

#include <openssl/evp.h>

#include "pqchat/crypto/openssl_raii.h"
#include "pqchat/util/result.h"

namespace pqchat::crypto {

struct MlDsa65KeyPair {
  EvpPkeyPtr private_key;
  std::vector<uint8_t> public_key;
};

class MlDsa65 {
 public:
  static Result<MlDsa65KeyPair> GenerateKeyPair();

  static Result<std::vector<uint8_t>> Sign(EVP_PKEY* private_key,
                                           const std::vector<uint8_t>& message);

  static Result<void> Verify(const std::vector<uint8_t>& public_key,
                             const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& signature);
};

}  // namespace pqchat::crypto
