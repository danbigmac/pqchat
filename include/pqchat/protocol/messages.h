#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pqchat/util/result.h"

namespace pqchat::protocol {

struct PrekeySelection {
  uint32_t signed_prekey_ec_id;
  uint32_t signed_prekey_pq_id;
  std::optional<uint32_t> one_time_ec_id;
  std::optional<uint32_t> one_time_pq_id;
};

struct InitialMessage {
  std::string session_id;
  std::string from_user;
  std::string to_user;

  std::vector<uint8_t> initiator_identity_sign_public_key;
  std::vector<uint8_t> initiator_identity_mldsa_public_key;
  std::vector<uint8_t> initiator_identity_dh_public_key;
  std::vector<uint8_t> initiator_ephemeral_ec_public_key;

  PrekeySelection selected_prekeys;

  std::vector<uint8_t> kem_ciphertext_signed_pq;
  std::optional<std::vector<uint8_t>> kem_ciphertext_one_time_pq;

  std::vector<uint8_t> transcript_hash;
  std::vector<uint8_t> handshake_signature_ed25519;
  std::vector<uint8_t> handshake_signature_mldsa65;

  std::vector<uint8_t> initial_nonce;
  std::vector<uint8_t> initial_ciphertext;
};

struct InitialTranscriptFields {
  std::string from_user;
  std::string to_user;

  std::vector<uint8_t> initiator_identity_sign_public_key;
  std::vector<uint8_t> initiator_identity_mldsa_public_key;
  std::vector<uint8_t> initiator_identity_dh_public_key;

  std::vector<uint8_t> responder_identity_sign_public_key;
  std::vector<uint8_t> responder_identity_mldsa_public_key;
  std::vector<uint8_t> responder_identity_dh_public_key;

  std::vector<uint8_t> initiator_ephemeral_ec_public_key;

  PrekeySelection selected_prekeys;

  std::vector<uint8_t> kem_ciphertext_signed_pq;
  std::optional<std::vector<uint8_t>> kem_ciphertext_one_time_pq;
};

struct MessageHeader {
  std::optional<std::vector<uint8_t>> sender_ratchet_public_key;
  uint64_t previous_chain_length = 0;
  uint64_t message_number = 0;
  uint32_t flags = 0;
};

struct ChatMessage {
  std::string session_id;
  std::string from_user;
  std::string to_user;
  MessageHeader header;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> ciphertext;
};

enum class EnvelopeType {
  kInitial,
  kChat,
};

struct Envelope {
  EnvelopeType type;
  std::optional<InitialMessage> initial;
  std::optional<ChatMessage> chat;

  static Envelope FromInitial(InitialMessage message);
  static Envelope FromChat(ChatMessage message);
};

Result<std::vector<uint8_t>> ComputeInitialTranscriptHash(
    const InitialTranscriptFields& fields);

Result<std::vector<uint8_t>> BuildChatAssociatedData(const ChatMessage& message);

}  // namespace pqchat::protocol
