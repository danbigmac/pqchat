#include "pqchat/protocol/messages.h"

#include "pqchat/crypto/hash.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/protocol/prekey_bundle.h"

namespace pqchat::protocol {
namespace {

void AppendUint32(std::vector<uint8_t>* out, uint32_t value) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

void AppendUint64(std::vector<uint8_t>* out, uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

void AppendBytes(std::vector<uint8_t>* out, const std::vector<uint8_t>& bytes) {
  AppendUint32(out, static_cast<uint32_t>(bytes.size()));
  out->insert(out->end(), bytes.begin(), bytes.end());
}

void AppendString(std::vector<uint8_t>* out, const std::string& value) {
  AppendBytes(out, std::vector<uint8_t>(value.begin(), value.end()));
}

}  // namespace

Envelope Envelope::FromInitial(InitialMessage message) {
  Envelope envelope;
  envelope.type = EnvelopeType::kInitial;
  envelope.initial = std::move(message);
  return envelope;
}

Envelope Envelope::FromChat(ChatMessage message) {
  Envelope envelope;
  envelope.type = EnvelopeType::kChat;
  envelope.chat = std::move(message);
  return envelope;
}

Result<std::vector<uint8_t>> ComputeInitialTranscriptHash(
    const InitialTranscriptFields& fields) {
  std::vector<uint8_t> canonical;
  AppendString(&canonical, "pqchat_initial_transcript_v1");
  AppendString(&canonical, fields.session_id);
  AppendString(&canonical, fields.from_user);
  AppendString(&canonical, fields.to_user);
  AppendString(&canonical, fields.version);
  AppendString(&canonical, fields.cipher_suite);

  AppendBytes(&canonical, fields.initiator_identity_sign_public_key);
  AppendBytes(&canonical, fields.initiator_identity_mldsa_public_key);
  AppendBytes(&canonical, fields.initiator_identity_dh_public_key);
  AppendBytes(&canonical, fields.responder_identity_sign_public_key);
  AppendBytes(&canonical, fields.responder_identity_mldsa_public_key);
  AppendBytes(&canonical, fields.responder_identity_dh_public_key);
  AppendBytes(&canonical, fields.initiator_ephemeral_ec_public_key);

  AppendUint32(&canonical, fields.selected_prekeys.signed_prekey_ec_id);
  AppendUint32(&canonical, fields.selected_prekeys.signed_prekey_pq_id);

  AppendUint32(&canonical, fields.selected_prekeys.one_time_ec_id.has_value() ? 1 : 0);
  if (fields.selected_prekeys.one_time_ec_id.has_value()) {
    AppendUint32(&canonical, *fields.selected_prekeys.one_time_ec_id);
  }

  AppendUint32(&canonical, fields.selected_prekeys.one_time_pq_id.has_value() ? 1 : 0);
  if (fields.selected_prekeys.one_time_pq_id.has_value()) {
    AppendUint32(&canonical, *fields.selected_prekeys.one_time_pq_id);
  }

  AppendBytes(&canonical, fields.kem_ciphertext_signed_pq);
  AppendUint32(&canonical, fields.kem_ciphertext_one_time_pq.has_value() ? 1 : 0);
  if (fields.kem_ciphertext_one_time_pq.has_value()) {
    AppendBytes(&canonical, *fields.kem_ciphertext_one_time_pq);
  }

  if (fields.version != kProtocolVersion) {
    return Result<std::vector<uint8_t>>::Err("unsupported initial message version");
  }
  if (fields.cipher_suite != kCipherSuite) {
    return Result<std::vector<uint8_t>>::Err("unsupported initial message cipher suite");
  }

  return crypto::Sha256(canonical);
}

Result<std::vector<uint8_t>> BuildChatAssociatedData(const ChatMessage& message) {
  std::vector<uint8_t> canonical;
  AppendString(&canonical, "pqchat_chat_ad_v1");
  AppendString(&canonical, message.session_id);
  AppendString(&canonical, message.from_user);
  AppendString(&canonical, message.to_user);

  AppendUint64(&canonical, message.header.previous_chain_length);
  AppendUint64(&canonical, message.header.message_number);
  AppendUint32(&canonical, message.header.flags);

  AppendUint32(&canonical, message.header.sender_ratchet_public_key.has_value() ? 1 : 0);
  if (message.header.sender_ratchet_public_key.has_value()) {
    AppendBytes(&canonical, *message.header.sender_ratchet_public_key);
  }

  return crypto::Sha256(canonical);
}

}  // namespace pqchat::protocol
