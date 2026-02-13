#include "pqchat/crypto/aead.h"

#include <cstring>

#include <openssl/evp.h>

#include "pqchat/crypto/openssl_raii.h"

namespace pqchat::crypto {

Result<std::vector<uint8_t>> AeadChaCha20Poly1305::Seal(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& ad) {
  if (key.size() != kKeySize) {
    return Result<std::vector<uint8_t>>::Err("invalid key size");
  }
  if (nonce.size() != kNonceSize) {
    return Result<std::vector<uint8_t>>::Err("invalid nonce size");
  }

  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_CIPHER_CTX_new failed");
  }

  if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr,
                         nullptr) != 1) {
    return Result<std::vector<uint8_t>>::Err("EncryptInit failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1) {
    return Result<std::vector<uint8_t>>::Err("SET_IVLEN failed");
  }

  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) !=
      1) {
    return Result<std::vector<uint8_t>>::Err("EncryptInit key/nonce failed");
  }

  int len = 0;
  if (!ad.empty()) {
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, ad.data(),
                          static_cast<int>(ad.size())) != 1) {
      return Result<std::vector<uint8_t>>::Err("EncryptUpdate AD failed");
    }
  }

  std::vector<uint8_t> out(plaintext.size() + kTagSize);
  if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1) {
    return Result<std::vector<uint8_t>>::Err("EncryptUpdate failed");
  }
  int ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + ciphertext_len, &len) != 1) {
    return Result<std::vector<uint8_t>>::Err("EncryptFinal failed");
  }
  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, kTagSize,
                          out.data() + ciphertext_len) != 1) {
    return Result<std::vector<uint8_t>>::Err("GET_TAG failed");
  }

  out.resize(ciphertext_len + kTagSize);
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> AeadChaCha20Poly1305::Open(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& ad) {
  if (key.size() != kKeySize) {
    return Result<std::vector<uint8_t>>::Err("invalid key size");
  }
  if (nonce.size() != kNonceSize) {
    return Result<std::vector<uint8_t>>::Err("invalid nonce size");
  }
  if (ciphertext.size() < kTagSize) {
    return Result<std::vector<uint8_t>>::Err("ciphertext too short");
  }

  const size_t tag_offset = ciphertext.size() - kTagSize;

  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("EVP_CIPHER_CTX_new failed");
  }

  if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr,
                         nullptr) != 1) {
    return Result<std::vector<uint8_t>>::Err("DecryptInit failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1) {
    return Result<std::vector<uint8_t>>::Err("SET_IVLEN failed");
  }

  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) !=
      1) {
    return Result<std::vector<uint8_t>>::Err("DecryptInit key/nonce failed");
  }

  int len = 0;
  if (!ad.empty()) {
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, ad.data(),
                          static_cast<int>(ad.size())) != 1) {
      return Result<std::vector<uint8_t>>::Err("DecryptUpdate AD failed");
    }
  }

  std::vector<uint8_t> plaintext(tag_offset);
  if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                        static_cast<int>(tag_offset)) != 1) {
    return Result<std::vector<uint8_t>>::Err("DecryptUpdate failed");
  }
  int plaintext_len = len;

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, kTagSize,
                          const_cast<uint8_t*>(ciphertext.data() + tag_offset)) !=
      1) {
    return Result<std::vector<uint8_t>>::Err("SET_TAG failed");
  }

  if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len) != 1) {
    return Result<std::vector<uint8_t>>::Err("DecryptFinal failed");
  }
  plaintext_len += len;
  plaintext.resize(plaintext_len);

  return Result<std::vector<uint8_t>>::Ok(std::move(plaintext));
}

std::vector<uint8_t> NonceFromCounter(uint64_t counter) {
  std::vector<uint8_t> nonce(AeadChaCha20Poly1305::kNonceSize, 0);
  for (int i = 0; i < 8; ++i) {
    nonce[nonce.size() - 1 - i] = static_cast<uint8_t>(counter & 0xFF);
    counter >>= 8;
  }
  return nonce;
}

}  // namespace pqchat::crypto
