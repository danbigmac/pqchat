#include "pqchat/crypto/hash.h"

#include <openssl/sha.h>

namespace pqchat::crypto {

Result<std::vector<uint8_t>> Sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  if (SHA256(data.data(), data.size(), hash.data()) == nullptr) {
    return Result<std::vector<uint8_t>>::Err("SHA256 failed");
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(hash));
}

}  // namespace pqchat::crypto
