#include "pqchat/crypto/hkdf.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include "pqchat/crypto/openssl_raii.h"

namespace pqchat::crypto {

Result<std::vector<uint8_t>> HkdfSha256(const std::vector<uint8_t>& ikm,
                                        const std::vector<uint8_t>& salt,
                                        const std::vector<uint8_t>& info,
                                        size_t output_len) {
  EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
  if (!kdf) {
    return Result<std::vector<uint8_t>>::Err("EVP_KDF_fetch(HKDF) failed");
  }

  EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_KDF_CTX_new failed");
  }

  std::vector<uint8_t> out(output_len);
  uint8_t empty = 0;
  unsigned char* ikm_ptr =
      const_cast<unsigned char*>(ikm.empty() ? &empty : ikm.data());
  unsigned char* salt_ptr =
      const_cast<unsigned char*>(salt.empty() ? &empty : salt.data());
  unsigned char* info_ptr =
      const_cast<unsigned char*>(info.empty() ? &empty : info.data());
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                       const_cast<char*>("SHA256"), 0),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_KEY,
          ikm_ptr,
          ikm.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT,
          salt_ptr,
          salt.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_INFO,
          info_ptr,
          info.size()),
      OSSL_PARAM_construct_end()};

  if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_KDF_derive failed");
  }

  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> HmacSha256(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& data) {
  unsigned int output_len = EVP_MAX_MD_SIZE;
  std::vector<uint8_t> out(output_len);

  unsigned char* result = HMAC(EVP_sha256(),
                               key.data(),
                               static_cast<int>(key.size()),
                               data.data(),
                               data.size(),
                               out.data(),
                               &output_len);
  if (result == nullptr) {
    return Result<std::vector<uint8_t>>::Err("HMAC failed");
  }

  out.resize(output_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

std::vector<uint8_t> Concat(const std::vector<std::vector<uint8_t>>& parts) {
  size_t total = 0;
  for (const auto& part : parts) {
    total += part.size();
  }

  std::vector<uint8_t> out;
  out.reserve(total);
  for (const auto& part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

std::vector<uint8_t> ToBytes(const std::string& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

}  // namespace pqchat::crypto
