#include "pqchat/crypto/x25519.h"

#include <openssl/evp.h>

#include "pqchat/crypto/openssl_raii.h"

namespace pqchat::crypto {

Result<X25519KeyPair> X25519::GenerateKeyPair() {
  EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
  if (!ctx) {
    return Result<X25519KeyPair>::Err("EVP_PKEY_CTX_new_id failed");
  }

  if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
    return Result<X25519KeyPair>::Err("EVP_PKEY_keygen_init failed");
  }

  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw_key) != 1) {
    return Result<X25519KeyPair>::Err("EVP_PKEY_keygen failed");
  }
  EvpPkeyPtr key(raw_key);

  std::vector<uint8_t> public_key(32);
  size_t public_len = public_key.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), public_key.data(), &public_len) != 1) {
    return Result<X25519KeyPair>::Err("get_raw_public_key failed");
  }
  public_key.resize(public_len);

  std::vector<uint8_t> private_key(32);
  size_t private_len = private_key.size();
  if (EVP_PKEY_get_raw_private_key(key.get(), private_key.data(), &private_len) !=
      1) {
    return Result<X25519KeyPair>::Err("get_raw_private_key failed");
  }
  private_key.resize(private_len);

  X25519KeyPair pair{SecureBuffer(std::move(private_key)), std::move(public_key)};
  return Result<X25519KeyPair>::Ok(std::move(pair));
}

Result<std::vector<uint8_t>> X25519::SharedSecret(
    const SecureBuffer& private_key,
    const std::vector<uint8_t>& peer_public_key) {
  EvpPkeyPtr private_pkey(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                   private_key.bytes().data(), private_key.size()));
  if (!private_pkey) {
    return Result<std::vector<uint8_t>>::Err("new_raw_private_key failed");
  }

  EvpPkeyPtr public_pkey(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size()));
  if (!public_pkey) {
    return Result<std::vector<uint8_t>>::Err("new_raw_public_key failed");
  }

  EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(private_pkey.get(), nullptr));
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_CTX_new failed");
  }

  if (EVP_PKEY_derive_init(ctx.get()) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_derive_init failed");
  }

  if (EVP_PKEY_derive_set_peer(ctx.get(), public_pkey.get()) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_derive_set_peer failed");
  }

  size_t secret_len = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_derive sizing failed");
  }

  std::vector<uint8_t> secret(secret_len);
  if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_derive failed");
  }

  secret.resize(secret_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(secret));
}

}  // namespace pqchat::crypto
