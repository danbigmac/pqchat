#pragma once

#include <memory>

#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace pqchat::crypto {

struct EvpPkeyDeleter {
  void operator()(EVP_PKEY* ptr) const {
    EVP_PKEY_free(ptr);
  }
};

struct EvpPkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ptr) const {
    EVP_PKEY_CTX_free(ptr);
  }
};

struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX* ptr) const {
    EVP_MD_CTX_free(ptr);
  }
};

struct EvpCipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* ptr) const {
    EVP_CIPHER_CTX_free(ptr);
  }
};

struct EvpKdfCtxDeleter {
  void operator()(EVP_KDF_CTX* ptr) const {
    EVP_KDF_CTX_free(ptr);
  }
};

struct EvpKdfDeleter {
  void operator()(EVP_KDF* ptr) const {
    EVP_KDF_free(ptr);
  }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

}  // namespace pqchat::crypto
