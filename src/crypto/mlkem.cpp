#include "pqchat/crypto/mlkem.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace pqchat::crypto {
namespace {

Result<EvpPkeyPtr> PublicKeyFromRaw(const std::vector<uint8_t>& public_key) {
  EvpPkeyCtxPtr fromdata_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr));
  if (!fromdata_ctx) {
    return Result<EvpPkeyPtr>::Err("ML-KEM-768 not available in OpenSSL provider");
  }

  if (EVP_PKEY_fromdata_init(fromdata_ctx.get()) != 1) {
    return Result<EvpPkeyPtr>::Err("EVP_PKEY_fromdata_init failed");
  }

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        const_cast<uint8_t*>(public_key.data()),
                                        public_key.size()),
      OSSL_PARAM_construct_end()};

  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_fromdata(fromdata_ctx.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY, params) !=
      1) {
    return Result<EvpPkeyPtr>::Err("EVP_PKEY_fromdata failed for public key");
  }

  return Result<EvpPkeyPtr>::Ok(EvpPkeyPtr(raw_pkey));
}

Result<EvpPkeyPtr> KeyPairFromRaw(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& public_key) {
  EvpPkeyCtxPtr fromdata_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr));
  if (!fromdata_ctx) {
    return Result<EvpPkeyPtr>::Err("ML-KEM-768 not available in OpenSSL provider");
  }

  if (EVP_PKEY_fromdata_init(fromdata_ctx.get()) != 1) {
    return Result<EvpPkeyPtr>::Err("EVP_PKEY_fromdata_init failed");
  }

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                        const_cast<uint8_t*>(private_key.data()),
                                        private_key.size()),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        const_cast<uint8_t*>(public_key.data()),
                                        public_key.size()),
      OSSL_PARAM_construct_end()};

  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_fromdata(fromdata_ctx.get(), &raw_pkey, EVP_PKEY_KEYPAIR, params) != 1) {
    return Result<EvpPkeyPtr>::Err("EVP_PKEY_fromdata failed for ML-KEM keypair");
  }

  return Result<EvpPkeyPtr>::Ok(EvpPkeyPtr(raw_pkey));
}

}  // namespace

Result<MlKemKeyPair> MlKem768::GenerateKeyPair() {
  EvpPkeyCtxPtr keygen_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr));
  if (!keygen_ctx) {
    return Result<MlKemKeyPair>::Err("ML-KEM-768 not available in OpenSSL provider");
  }

  if (EVP_PKEY_keygen_init(keygen_ctx.get()) != 1) {
    return Result<MlKemKeyPair>::Err("EVP_PKEY_keygen_init failed");
  }

  EVP_PKEY* raw_private = nullptr;
  if (EVP_PKEY_generate(keygen_ctx.get(), &raw_private) != 1) {
    return Result<MlKemKeyPair>::Err("EVP_PKEY_generate failed");
  }

  EvpPkeyPtr private_key(raw_private);

  size_t pub_len = 0;
  if (EVP_PKEY_get_octet_string_param(private_key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      nullptr, 0, &pub_len) != 1) {
    return Result<MlKemKeyPair>::Err("EVP_PKEY_get_octet_string_param size failed");
  }

  std::vector<uint8_t> public_key(pub_len);
  if (EVP_PKEY_get_octet_string_param(private_key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      public_key.data(), public_key.size(), &pub_len) !=
      1) {
    return Result<MlKemKeyPair>::Err("EVP_PKEY_get_octet_string_param failed");
  }
  public_key.resize(pub_len);

  MlKemKeyPair pair{std::move(private_key), std::move(public_key)};
  return Result<MlKemKeyPair>::Ok(std::move(pair));
}

Result<MlKemKeyPair> MlKem768::FromPrivateKey(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& public_key) {
  auto key_result = KeyPairFromRaw(private_key, public_key);
  if (!key_result.ok()) {
    return Result<MlKemKeyPair>::Err(key_result.error());
  }
  MlKemKeyPair pair{key_result.take_value(), public_key};
  return Result<MlKemKeyPair>::Ok(std::move(pair));
}

Result<std::vector<uint8_t>> MlKem768::ExportPrivateKey(EVP_PKEY* private_key) {
  if (private_key == nullptr) {
    return Result<std::vector<uint8_t>>::Err("private key is null");
  }

  size_t priv_len = 0;
  if (EVP_PKEY_get_octet_string_param(private_key, OSSL_PKEY_PARAM_PRIV_KEY,
                                      nullptr, 0, &priv_len) != 1) {
    return Result<std::vector<uint8_t>>::Err("get private key size failed");
  }

  std::vector<uint8_t> out(priv_len);
  if (EVP_PKEY_get_octet_string_param(private_key, OSSL_PKEY_PARAM_PRIV_KEY,
                                      out.data(), out.size(), &priv_len) != 1) {
    return Result<std::vector<uint8_t>>::Err("get private key failed");
  }
  out.resize(priv_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<MlKemEncapResult> MlKem768::Encapsulate(
    const std::vector<uint8_t>& public_key) {
  auto peer_key_result = PublicKeyFromRaw(public_key);
  if (!peer_key_result.ok()) {
    return Result<MlKemEncapResult>::Err(peer_key_result.error());
  }
  EvpPkeyPtr peer_key = peer_key_result.take_value();

  EvpPkeyCtxPtr enc_ctx(EVP_PKEY_CTX_new(peer_key.get(), nullptr));
  if (!enc_ctx) {
    return Result<MlKemEncapResult>::Err("EVP_PKEY_CTX_new failed");
  }

  if (EVP_PKEY_encapsulate_init(enc_ctx.get(), nullptr) != 1) {
    return Result<MlKemEncapResult>::Err("EVP_PKEY_encapsulate_init failed");
  }

  size_t ciphertext_len = 0;
  size_t secret_len = 0;
  if (EVP_PKEY_encapsulate(enc_ctx.get(), nullptr, &ciphertext_len, nullptr,
                           &secret_len) != 1) {
    return Result<MlKemEncapResult>::Err("EVP_PKEY_encapsulate sizing failed");
  }

  MlKemEncapResult result;
  result.ciphertext.resize(ciphertext_len);
  result.shared_secret.resize(secret_len);

  if (EVP_PKEY_encapsulate(enc_ctx.get(), result.ciphertext.data(), &ciphertext_len,
                           result.shared_secret.data(), &secret_len) != 1) {
    return Result<MlKemEncapResult>::Err("EVP_PKEY_encapsulate failed");
  }

  result.ciphertext.resize(ciphertext_len);
  result.shared_secret.resize(secret_len);
  return Result<MlKemEncapResult>::Ok(std::move(result));
}

Result<std::vector<uint8_t>> MlKem768::Decapsulate(
    EVP_PKEY* private_key,
    const std::vector<uint8_t>& ciphertext) {
  if (private_key == nullptr) {
    return Result<std::vector<uint8_t>>::Err("private key is null");
  }

  EvpPkeyCtxPtr dec_ctx(EVP_PKEY_CTX_new(private_key, nullptr));
  if (!dec_ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_CTX_new failed");
  }

  if (EVP_PKEY_decapsulate_init(dec_ctx.get(), nullptr) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_decapsulate_init failed");
  }

  size_t secret_len = 0;
  if (EVP_PKEY_decapsulate(dec_ctx.get(), nullptr, &secret_len, ciphertext.data(),
                           ciphertext.size()) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_decapsulate sizing failed");
  }

  std::vector<uint8_t> secret(secret_len);
  if (EVP_PKEY_decapsulate(dec_ctx.get(), secret.data(), &secret_len,
                           ciphertext.data(), ciphertext.size()) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_PKEY_decapsulate failed");
  }

  secret.resize(secret_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(secret));
}

}  // namespace pqchat::crypto
