#pragma once

#include <cstdint>
#include <vector>

#include <openssl/evp.h>

#include "pqchat/crypto/openssl_raii.h"
#include "pqchat/util/result.h"

namespace pqchat::crypto {

struct MlKemKeyPair {
  EvpPkeyPtr private_key;
  std::vector<uint8_t> public_key;
};

struct MlKemEncapResult {
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> shared_secret;
};

class MlKem768 {
 public:
  static Result<MlKemKeyPair> GenerateKeyPair();
  static Result<MlKemKeyPair> FromPrivateKey(
      const std::vector<uint8_t>& private_key,
      const std::vector<uint8_t>& public_key);

  static Result<std::vector<uint8_t>> ExportPrivateKey(EVP_PKEY* private_key);

  static Result<MlKemEncapResult> Encapsulate(
      const std::vector<uint8_t>& public_key);

  static Result<std::vector<uint8_t>> Decapsulate(
      EVP_PKEY* private_key,
      const std::vector<uint8_t>& ciphertext);
};

}  // namespace pqchat::crypto
