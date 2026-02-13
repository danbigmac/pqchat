#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "pqchat/crypto/mlkem.h"
#include "pqchat/crypto/secure_buffer.h"
#include "pqchat/crypto/x25519.h"
#include "pqchat/util/result.h"

namespace pqchat::protocol {

inline constexpr const char* kProtocolVersion = "pqchat-v1";
inline constexpr const char* kCipherSuite = "X25519+ML-KEM-768+ChaCha20-Poly1305+HKDF-SHA256";

struct SignedPrekeyEc {
  uint32_t id;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> signature_ed25519;
  std::vector<uint8_t> signature_mldsa65;
};

struct SignedPrekeyPq {
  uint32_t id;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> signature_ed25519;
  std::vector<uint8_t> signature_mldsa65;
};

struct OneTimePrekeyEc {
  uint32_t id;
  std::vector<uint8_t> public_key;
};

struct OneTimePrekeyPq {
  uint32_t id;
  std::vector<uint8_t> public_key;
};

struct PrekeyBundle {
  std::string user_id;
  std::vector<uint8_t> identity_sign_public_key;
  std::vector<uint8_t> identity_mldsa_public_key;
  std::vector<uint8_t> identity_dh_public_key;
  SignedPrekeyEc signed_prekey_ec;
  SignedPrekeyPq signed_prekey_pq;
  std::optional<OneTimePrekeyEc> one_time_ec;
  std::optional<OneTimePrekeyPq> one_time_pq;
  std::string version = kProtocolVersion;
  std::string cipher_suite = kCipherSuite;
};

struct LocalPrekeyState {
  SignedPrekeyEc signed_prekey_ec_public;
  crypto::X25519KeyPair signed_prekey_ec_private;

  SignedPrekeyPq signed_prekey_pq_public;
  crypto::MlKemKeyPair signed_prekey_pq_private;

  std::vector<OneTimePrekeyEc> one_time_ec_public;
  std::vector<crypto::X25519KeyPair> one_time_ec_private;

  std::vector<OneTimePrekeyPq> one_time_pq_public;
  std::vector<crypto::MlKemKeyPair> one_time_pq_private;
};

std::vector<uint8_t> BuildEcPrekeySignInput(uint32_t key_id,
                                            const std::vector<uint8_t>& public_key);

std::vector<uint8_t> BuildPqPrekeySignInput(uint32_t key_id,
                                            const std::vector<uint8_t>& public_key);

Result<void> VerifyPrekeyBundleSignatures(const PrekeyBundle& bundle);

}  // namespace pqchat::protocol
