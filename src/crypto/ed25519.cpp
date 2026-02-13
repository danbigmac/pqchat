#include "pqchat/crypto/ed25519.h"

#include <openssl/evp.h>

#include "pqchat/crypto/openssl_raii.h"

namespace pqchat::crypto {

Result<Ed25519KeyPair> Ed25519::GenerateKeyPair() {
  EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
  if (!ctx) {
    return Result<Ed25519KeyPair>::Err("EVP_PKEY_CTX_new_id failed");
  }

  if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
    return Result<Ed25519KeyPair>::Err("EVP_PKEY_keygen_init failed");
  }

  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw_key) != 1) {
    return Result<Ed25519KeyPair>::Err("EVP_PKEY_keygen failed");
  }
  EvpPkeyPtr key(raw_key);

  std::vector<uint8_t> public_key(32);
  size_t public_len = public_key.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), public_key.data(), &public_len) != 1) {
    return Result<Ed25519KeyPair>::Err("get_raw_public_key failed");
  }
  public_key.resize(public_len);

  std::vector<uint8_t> private_key(32);
  size_t private_len = private_key.size();
  if (EVP_PKEY_get_raw_private_key(key.get(), private_key.data(), &private_len) !=
      1) {
    return Result<Ed25519KeyPair>::Err("get_raw_private_key failed");
  }
  private_key.resize(private_len);

  Ed25519KeyPair pair{SecureBuffer(std::move(private_key)), std::move(public_key)};
  return Result<Ed25519KeyPair>::Ok(std::move(pair));
}

Result<std::vector<uint8_t>> Ed25519::Sign(const SecureBuffer& private_key,
                                           const std::vector<uint8_t>& message) {
  EvpPkeyPtr key(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, private_key.bytes().data(), private_key.size()));
  if (!key) {
    return Result<std::vector<uint8_t>>::Err("new_raw_private_key failed");
  }

  EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
  if (!md_ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_MD_CTX_new failed");
  }

  if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    return Result<std::vector<uint8_t>>::Err("DigestSignInit failed");
  }

  size_t sig_len = 0;
  if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, message.data(),
                     message.size()) != 1) {
    return Result<std::vector<uint8_t>>::Err("DigestSign sizing failed");
  }

  std::vector<uint8_t> signature(sig_len);
  if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, message.data(),
                     message.size()) != 1) {
    return Result<std::vector<uint8_t>>::Err("DigestSign failed");
  }

  signature.resize(sig_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(signature));
}

Result<void> Ed25519::Verify(const std::vector<uint8_t>& public_key,
                             const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& signature) {
  EvpPkeyPtr key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                             public_key.data(), public_key.size()));
  if (!key) {
    return Result<void>::Err("new_raw_public_key failed");
  }

  EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
  if (!md_ctx) {
    return Result<void>::Err("EVP_MD_CTX_new failed");
  }

  if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    return Result<void>::Err("DigestVerifyInit failed");
  }

  if (EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(),
                       message.data(), message.size()) != 1) {
    return Result<void>::Err("signature verification failed");
  }

  return Result<void>::Ok();
}

}  // namespace pqchat::crypto
