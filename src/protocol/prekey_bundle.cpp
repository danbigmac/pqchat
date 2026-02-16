#include "pqchat/protocol/prekey_bundle.h"

#include <array>

#include "pqchat/crypto/ed25519.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"

namespace pqchat::protocol {
namespace {

void AppendUint32(std::vector<uint8_t>* out, uint32_t value) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

void AppendWithLength(std::vector<uint8_t>* out,
                      const std::vector<uint8_t>& bytes) {
  AppendUint32(out, static_cast<uint32_t>(bytes.size()));
  out->insert(out->end(), bytes.begin(), bytes.end());
}

std::vector<uint8_t> ToTagged(const char* tag,
                              uint32_t key_id,
                              const std::vector<uint8_t>& key) {
  std::vector<uint8_t> out;
  const auto tag_bytes = crypto::ToBytes(tag);
  AppendWithLength(&out, tag_bytes);
  AppendUint32(&out, key_id);
  AppendWithLength(&out, key);
  return out;
}

void AppendString(std::vector<uint8_t>* out, const std::string& value) {
  AppendWithLength(out, crypto::ToBytes(value));
}

}  // namespace

std::vector<uint8_t> BuildEcPrekeySignInput(uint32_t key_id,
                                            const std::vector<uint8_t>& public_key) {
  return ToTagged("pqchat_ec_prekey_v1", key_id, public_key);
}

std::vector<uint8_t> BuildPqPrekeySignInput(uint32_t key_id,
                                            const std::vector<uint8_t>& public_key) {
  return ToTagged("pqchat_pq_prekey_v1", key_id, public_key);
}

std::vector<uint8_t> BuildBundleSignInput(const PrekeyBundle& bundle) {
  std::vector<uint8_t> out;
  AppendString(&out, "pqchat_bundle_sig_v2");
  AppendString(&out, bundle.user_id);
  AppendWithLength(&out, bundle.identity_sign_public_key);
  AppendWithLength(&out, bundle.identity_mldsa_public_key);
  AppendWithLength(&out, bundle.identity_dh_public_key);

  AppendUint32(&out, bundle.signed_prekey_ec.id);
  AppendWithLength(&out, bundle.signed_prekey_ec.public_key);
  AppendWithLength(&out, bundle.signed_prekey_ec.signature_ed25519);
  AppendWithLength(&out, bundle.signed_prekey_ec.signature_mldsa65);

  AppendUint32(&out, bundle.signed_prekey_pq.id);
  AppendWithLength(&out, bundle.signed_prekey_pq.public_key);
  AppendWithLength(&out, bundle.signed_prekey_pq.signature_ed25519);
  AppendWithLength(&out, bundle.signed_prekey_pq.signature_mldsa65);

  AppendString(&out, bundle.version);
  AppendString(&out, bundle.cipher_suite);
  return out;
}

Result<void> VerifyPrekeyBundleSignatures(const PrekeyBundle& bundle) {
  if (bundle.version != kProtocolVersion) {
    return Result<void>::Err("unsupported bundle version");
  }
  if (bundle.cipher_suite != kCipherSuite) {
    return Result<void>::Err("unsupported bundle cipher suite");
  }

  auto ec_input = BuildEcPrekeySignInput(bundle.signed_prekey_ec.id,
                                         bundle.signed_prekey_ec.public_key);
  auto ec_verify = crypto::Ed25519::Verify(bundle.identity_sign_public_key,
                                           ec_input,
                                           bundle.signed_prekey_ec.signature_ed25519);
  if (!ec_verify.ok()) {
    return Result<void>::Err("signed_prekey_ec ed25519 signature invalid: " +
                             ec_verify.error());
  }

  auto ec_verify_mldsa = crypto::MlDsa65::Verify(bundle.identity_mldsa_public_key,
                                                 ec_input,
                                                 bundle.signed_prekey_ec.signature_mldsa65);
  if (!ec_verify_mldsa.ok()) {
    return Result<void>::Err("signed_prekey_ec mldsa signature invalid: " +
                             ec_verify_mldsa.error());
  }

  auto pq_input = BuildPqPrekeySignInput(bundle.signed_prekey_pq.id,
                                         bundle.signed_prekey_pq.public_key);
  auto pq_verify = crypto::Ed25519::Verify(bundle.identity_sign_public_key,
                                           pq_input,
                                           bundle.signed_prekey_pq.signature_ed25519);
  if (!pq_verify.ok()) {
    return Result<void>::Err("signed_prekey_pq ed25519 signature invalid: " +
                             pq_verify.error());
  }

  auto pq_verify_mldsa = crypto::MlDsa65::Verify(bundle.identity_mldsa_public_key,
                                                 pq_input,
                                                 bundle.signed_prekey_pq.signature_mldsa65);
  if (!pq_verify_mldsa.ok()) {
    return Result<void>::Err("signed_prekey_pq mldsa signature invalid: " +
                             pq_verify_mldsa.error());
  }

  auto bundle_sign_input = BuildBundleSignInput(bundle);
  auto bundle_verify = crypto::Ed25519::Verify(bundle.identity_sign_public_key,
                                               bundle_sign_input,
                                               bundle.bundle_signature_ed25519);
  if (!bundle_verify.ok()) {
    return Result<void>::Err("bundle ed25519 signature invalid: " +
                             bundle_verify.error());
  }

  auto bundle_verify_mldsa = crypto::MlDsa65::Verify(bundle.identity_mldsa_public_key,
                                                     bundle_sign_input,
                                                     bundle.bundle_signature_mldsa65);
  if (!bundle_verify_mldsa.ok()) {
    return Result<void>::Err("bundle mldsa signature invalid: " +
                             bundle_verify_mldsa.error());
  }

  return Result<void>::Ok();
}

}  // namespace pqchat::protocol
