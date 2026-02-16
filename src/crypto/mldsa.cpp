#include "pqchat/crypto/mldsa.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace pqchat::crypto {
namespace {

Result<EvpPkeyPtr> PublicKeyFromRaw(const std::vector<uint8_t>& public_key) {
  EvpPkeyCtxPtr fromdata_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr));
  if (!fromdata_ctx) {
    return Result<EvpPkeyPtr>::Err("ML-DSA-65 not available in OpenSSL provider");
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
    return Result<EvpPkeyPtr>::Err("EVP_PKEY_fromdata failed for ML-DSA public key");
  }

  return Result<EvpPkeyPtr>::Ok(EvpPkeyPtr(raw_pkey));
}

Result<EvpPkeyPtr> KeyPairFromRaw(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& public_key) {
  EvpPkeyCtxPtr fromdata_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr));
  if (!fromdata_ctx) {
    return Result<EvpPkeyPtr>::Err("ML-DSA-65 not available in OpenSSL provider");
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
    return Result<EvpPkeyPtr>::Err("EVP_PKEY_fromdata failed for ML-DSA keypair");
  }
  return Result<EvpPkeyPtr>::Ok(EvpPkeyPtr(raw_pkey));
}

}  // namespace

Result<MlDsa65KeyPair> MlDsa65::GenerateKeyPair() {
  EvpPkeyCtxPtr keygen_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr));
  if (!keygen_ctx) {
    return Result<MlDsa65KeyPair>::Err("ML-DSA-65 not available in OpenSSL provider");
  }

  if (EVP_PKEY_keygen_init(keygen_ctx.get()) != 1) {
    return Result<MlDsa65KeyPair>::Err("EVP_PKEY_keygen_init failed");
  }

  EVP_PKEY* raw_private = nullptr;
  if (EVP_PKEY_generate(keygen_ctx.get(), &raw_private) != 1) {
    return Result<MlDsa65KeyPair>::Err("EVP_PKEY_generate failed");
  }

  EvpPkeyPtr private_key(raw_private);

  size_t pub_len = 0;
  if (EVP_PKEY_get_octet_string_param(private_key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      nullptr, 0, &pub_len) != 1) {
    return Result<MlDsa65KeyPair>::Err("get_octet_string_param size failed");
  }

  std::vector<uint8_t> public_key(pub_len);
  if (EVP_PKEY_get_octet_string_param(private_key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      public_key.data(), public_key.size(), &pub_len) !=
      1) {
    return Result<MlDsa65KeyPair>::Err("get_octet_string_param failed");
  }

  public_key.resize(pub_len);
  MlDsa65KeyPair pair{std::move(private_key), std::move(public_key)};
  return Result<MlDsa65KeyPair>::Ok(std::move(pair));
}

Result<MlDsa65KeyPair> MlDsa65::FromPrivateKey(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& public_key) {
  auto key_result = KeyPairFromRaw(private_key, public_key);
  if (!key_result.ok()) {
    return Result<MlDsa65KeyPair>::Err(key_result.error());
  }
  MlDsa65KeyPair pair{key_result.take_value(), public_key};
  return Result<MlDsa65KeyPair>::Ok(std::move(pair));
}

Result<std::vector<uint8_t>> MlDsa65::ExportPrivateKey(EVP_PKEY* private_key) {
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

Result<std::vector<uint8_t>> MlDsa65::Sign(EVP_PKEY* private_key,
                                           const std::vector<uint8_t>& message) {
  if (private_key == nullptr) {
    return Result<std::vector<uint8_t>>::Err("private key is null");
  }

  EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
  if (!md_ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_MD_CTX_new failed");
  }

  if (EVP_DigestSignInit_ex(md_ctx.get(), nullptr, nullptr, nullptr, nullptr, private_key,
                            nullptr) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_DigestSignInit_ex failed");
  }

  size_t sig_len = 0;
  if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, message.data(), message.size()) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_DigestSign sizing failed");
  }

  std::vector<uint8_t> signature(sig_len);
  if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, message.data(),
                     message.size()) != 1) {
    return Result<std::vector<uint8_t>>::Err("EVP_DigestSign failed");
  }

  signature.resize(sig_len);
  return Result<std::vector<uint8_t>>::Ok(std::move(signature));
}

Result<void> MlDsa65::Verify(const std::vector<uint8_t>& public_key,
                             const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& signature) {
  auto pub = PublicKeyFromRaw(public_key);
  if (!pub.ok()) {
    return Result<void>::Err(pub.error());
  }

  EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
  if (!md_ctx) {
    return Result<void>::Err("EVP_MD_CTX_new failed");
  }

  if (EVP_DigestVerifyInit_ex(md_ctx.get(), nullptr, nullptr, nullptr, nullptr,
                              pub.value().get(), nullptr) != 1) {
    return Result<void>::Err("EVP_DigestVerifyInit_ex failed");
  }

  if (EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(), message.data(),
                       message.size()) != 1) {
    return Result<void>::Err("ML-DSA signature verification failed");
  }

  return Result<void>::Ok();
}

}  // namespace pqchat::crypto
