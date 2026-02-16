#include "pqchat/protocol/serialization.h"

#include <cstddef>
#include <cstdint>

namespace pqchat::protocol {
namespace {

constexpr size_t kMaxSerializedInputBytes = 8 * 1024 * 1024;
constexpr uint32_t kMaxFieldBytes = 1024 * 1024;
constexpr uint32_t kMaxStringBytes = 64 * 1024;
constexpr uint32_t kMaxOneTimePrekeys = 4096;
constexpr uint32_t kMaxEnvelopeVectorItems = 4096;

Result<void> ValidateInputSize(const std::vector<uint8_t>& bytes,
                               const char* label) {
  if (bytes.size() > kMaxSerializedInputBytes) {
    return Result<void>::Err(std::string(label) + " too large");
  }
  return Result<void>::Ok();
}

class Writer {
 public:
  void U8(uint8_t value) {
    out_.push_back(value);
  }

  void U32(uint32_t value) {
    out_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out_.push_back(static_cast<uint8_t>(value & 0xFF));
  }

  void U64(uint64_t value) {
    for (int i = 7; i >= 0; --i) {
      out_.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
  }

  void Bytes(const std::vector<uint8_t>& value) {
    U32(static_cast<uint32_t>(value.size()));
    out_.insert(out_.end(), value.begin(), value.end());
  }

  void String(const std::string& value) {
    Bytes(std::vector<uint8_t>(value.begin(), value.end()));
  }

  void OptionalU32(const std::optional<uint32_t>& value) {
    U8(value.has_value() ? 1 : 0);
    if (value.has_value()) {
      U32(*value);
    }
  }

  void OptionalBytes(const std::optional<std::vector<uint8_t>>& value) {
    U8(value.has_value() ? 1 : 0);
    if (value.has_value()) {
      Bytes(*value);
    }
  }

  std::vector<uint8_t> Take() {
    return std::move(out_);
  }

 private:
  std::vector<uint8_t> out_;
};

class Reader {
 public:
  explicit Reader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}

  bool U8(uint8_t* out) {
    if (pos_ + 1 > bytes_.size()) {
      error_ = "unexpected EOF while reading u8";
      return false;
    }
    *out = bytes_[pos_++];
    return true;
  }

  bool U32(uint32_t* out) {
    if (pos_ + 4 > bytes_.size()) {
      error_ = "unexpected EOF while reading u32";
      return false;
    }
    *out = (static_cast<uint32_t>(bytes_[pos_]) << 24) |
           (static_cast<uint32_t>(bytes_[pos_ + 1]) << 16) |
           (static_cast<uint32_t>(bytes_[pos_ + 2]) << 8) |
           static_cast<uint32_t>(bytes_[pos_ + 3]);
    pos_ += 4;
    return true;
  }

  bool U64(uint64_t* out) {
    if (pos_ + 8 > bytes_.size()) {
      error_ = "unexpected EOF while reading u64";
      return false;
    }

    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
      value = (value << 8) | bytes_[pos_ + i];
    }
    pos_ += 8;
    *out = value;
    return true;
  }

  bool Bytes(std::vector<uint8_t>* out,
             uint32_t max_len = kMaxFieldBytes,
             const char* label = "bytes") {
    uint32_t len = 0;
    if (!U32(&len)) {
      return false;
    }
    if (len > max_len) {
      error_ = "decoded ";
      error_ += label;
      error_ += " exceeds limit";
      return false;
    }
    if (pos_ + len > bytes_.size()) {
      error_ = "unexpected EOF while reading bytes";
      return false;
    }
    out->assign(bytes_.begin() + static_cast<long>(pos_),
                bytes_.begin() + static_cast<long>(pos_ + len));
    pos_ += len;
    return true;
  }

  bool String(std::string* out, uint32_t max_len = kMaxStringBytes) {
    std::vector<uint8_t> bytes;
    if (!Bytes(&bytes, max_len, "string")) {
      return false;
    }
    out->assign(bytes.begin(), bytes.end());
    return true;
  }

  bool LimitU32(uint32_t value, uint32_t max, const char* label) {
    if (value > max) {
      error_ = "decoded ";
      error_ += label;
      error_ += " exceeds limit";
      return false;
    }
    return true;
  }

  bool OptionalU32(std::optional<uint32_t>* out) {
    uint8_t present = 0;
    if (!U8(&present)) {
      return false;
    }
    if (present == 0) {
      *out = std::nullopt;
      return true;
    }
    if (present != 1) {
      error_ = "invalid optional u32 tag";
      return false;
    }

    uint32_t value = 0;
    if (!U32(&value)) {
      return false;
    }
    *out = value;
    return true;
  }

  bool OptionalBytes(std::optional<std::vector<uint8_t>>* out) {
    uint8_t present = 0;
    if (!U8(&present)) {
      return false;
    }
    if (present == 0) {
      *out = std::nullopt;
      return true;
    }
    if (present != 1) {
      error_ = "invalid optional bytes tag";
      return false;
    }

    std::vector<uint8_t> value;
    if (!Bytes(&value)) {
      return false;
    }
    *out = std::move(value);
    return true;
  }

  [[nodiscard]] bool Finished() const { return pos_ == bytes_.size(); }
  [[nodiscard]] const std::string& error() const { return error_; }

 private:
  const std::vector<uint8_t>& bytes_;
  size_t pos_ = 0;
  std::string error_;
};

void WritePrekeySelection(Writer* writer, const PrekeySelection& selection) {
  writer->U32(selection.signed_prekey_ec_id);
  writer->U32(selection.signed_prekey_pq_id);
  writer->OptionalU32(selection.one_time_ec_id);
  writer->OptionalU32(selection.one_time_pq_id);
}

bool ReadPrekeySelection(Reader* reader, PrekeySelection* selection) {
  return reader->U32(&selection->signed_prekey_ec_id) &&
         reader->U32(&selection->signed_prekey_pq_id) &&
         reader->OptionalU32(&selection->one_time_ec_id) &&
         reader->OptionalU32(&selection->one_time_pq_id);
}

void WriteMessageHeader(Writer* writer, const MessageHeader& header) {
  writer->OptionalBytes(header.sender_ratchet_public_key);
  writer->U64(header.previous_chain_length);
  writer->U64(header.message_number);
  writer->U32(header.flags);
}

bool ReadMessageHeader(Reader* reader, MessageHeader* header) {
  return reader->OptionalBytes(&header->sender_ratchet_public_key) &&
         reader->U64(&header->previous_chain_length) &&
         reader->U64(&header->message_number) && reader->U32(&header->flags);
}

void WriteInitialMessage(Writer* writer, const InitialMessage& message) {
  writer->String(message.session_id);
  writer->String(message.from_user);
  writer->String(message.to_user);
  writer->String(message.version);
  writer->String(message.cipher_suite);
  writer->Bytes(message.initiator_identity_sign_public_key);
  writer->Bytes(message.initiator_identity_mldsa_public_key);
  writer->Bytes(message.initiator_identity_dh_public_key);
  writer->Bytes(message.initiator_ephemeral_ec_public_key);
  WritePrekeySelection(writer, message.selected_prekeys);
  writer->Bytes(message.kem_ciphertext_signed_pq);
  writer->OptionalBytes(message.kem_ciphertext_one_time_pq);
  writer->Bytes(message.transcript_hash);
  writer->Bytes(message.handshake_signature_ed25519);
  writer->Bytes(message.handshake_signature_mldsa65);
  writer->Bytes(message.initial_nonce);
  writer->Bytes(message.initial_ciphertext);
}

bool ReadInitialMessage(Reader* reader, InitialMessage* message) {
  return reader->String(&message->session_id) && reader->String(&message->from_user) &&
         reader->String(&message->to_user) && reader->String(&message->version) &&
         reader->String(&message->cipher_suite) &&
         reader->Bytes(&message->initiator_identity_sign_public_key) &&
         reader->Bytes(&message->initiator_identity_mldsa_public_key) &&
         reader->Bytes(&message->initiator_identity_dh_public_key) &&
         reader->Bytes(&message->initiator_ephemeral_ec_public_key) &&
         ReadPrekeySelection(reader, &message->selected_prekeys) &&
         reader->Bytes(&message->kem_ciphertext_signed_pq) &&
         reader->OptionalBytes(&message->kem_ciphertext_one_time_pq) &&
         reader->Bytes(&message->transcript_hash) &&
         reader->Bytes(&message->handshake_signature_ed25519) &&
         reader->Bytes(&message->handshake_signature_mldsa65) &&
         reader->Bytes(&message->initial_nonce) &&
         reader->Bytes(&message->initial_ciphertext);
}

void WriteChatMessage(Writer* writer, const ChatMessage& message) {
  writer->String(message.session_id);
  writer->String(message.from_user);
  writer->String(message.to_user);
  WriteMessageHeader(writer, message.header);
  writer->Bytes(message.nonce);
  writer->Bytes(message.ciphertext);
}

bool ReadChatMessage(Reader* reader, ChatMessage* message) {
  return reader->String(&message->session_id) && reader->String(&message->from_user) &&
         reader->String(&message->to_user) &&
         ReadMessageHeader(reader, &message->header) && reader->Bytes(&message->nonce) &&
         reader->Bytes(&message->ciphertext);
}

void WriteSignedPrekeyEc(Writer* writer, const SignedPrekeyEc& spk) {
  writer->U32(spk.id);
  writer->Bytes(spk.public_key);
  writer->Bytes(spk.signature_ed25519);
  writer->Bytes(spk.signature_mldsa65);
}

bool ReadSignedPrekeyEc(Reader* reader, SignedPrekeyEc* spk) {
  return reader->U32(&spk->id) && reader->Bytes(&spk->public_key) &&
         reader->Bytes(&spk->signature_ed25519) &&
         reader->Bytes(&spk->signature_mldsa65);
}

void WriteSignedPrekeyPq(Writer* writer, const SignedPrekeyPq& spk) {
  writer->U32(spk.id);
  writer->Bytes(spk.public_key);
  writer->Bytes(spk.signature_ed25519);
  writer->Bytes(spk.signature_mldsa65);
}

bool ReadSignedPrekeyPq(Reader* reader, SignedPrekeyPq* spk) {
  return reader->U32(&spk->id) && reader->Bytes(&spk->public_key) &&
         reader->Bytes(&spk->signature_ed25519) &&
         reader->Bytes(&spk->signature_mldsa65);
}

void WriteOneTimeEc(Writer* writer, const std::vector<OneTimePrekeyEc>& one_time) {
  writer->U32(static_cast<uint32_t>(one_time.size()));
  for (const auto& key : one_time) {
    writer->U32(key.id);
    writer->Bytes(key.public_key);
  }
}

bool ReadOneTimeEc(Reader* reader, std::vector<OneTimePrekeyEc>* one_time) {
  uint32_t count = 0;
  if (!reader->U32(&count)) {
    return false;
  }
  if (!reader->LimitU32(count, kMaxOneTimePrekeys, "one-time EC prekey count")) {
    return false;
  }

  one_time->clear();
  one_time->reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    OneTimePrekeyEc out;
    if (!reader->U32(&out.id) || !reader->Bytes(&out.public_key)) {
      return false;
    }
    one_time->push_back(std::move(out));
  }
  return true;
}

void WriteOneTimePq(Writer* writer, const std::vector<OneTimePrekeyPq>& one_time) {
  writer->U32(static_cast<uint32_t>(one_time.size()));
  for (const auto& key : one_time) {
    writer->U32(key.id);
    writer->Bytes(key.public_key);
  }
}

bool ReadOneTimePq(Reader* reader, std::vector<OneTimePrekeyPq>* one_time) {
  uint32_t count = 0;
  if (!reader->U32(&count)) {
    return false;
  }
  if (!reader->LimitU32(count, kMaxOneTimePrekeys, "one-time PQ prekey count")) {
    return false;
  }

  one_time->clear();
  one_time->reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    OneTimePrekeyPq out;
    if (!reader->U32(&out.id) || !reader->Bytes(&out.public_key)) {
      return false;
    }
    one_time->push_back(std::move(out));
  }
  return true;
}

}  // namespace

Result<std::vector<uint8_t>> SerializePrekeyBundle(const PrekeyBundle& bundle) {
  Writer writer;
  writer.String(bundle.user_id);
  writer.Bytes(bundle.identity_sign_public_key);
  writer.Bytes(bundle.identity_mldsa_public_key);
  writer.Bytes(bundle.identity_dh_public_key);
  WriteSignedPrekeyEc(&writer, bundle.signed_prekey_ec);
  WriteSignedPrekeyPq(&writer, bundle.signed_prekey_pq);
  WriteOneTimeEc(&writer, bundle.one_time_ec);
  WriteOneTimePq(&writer, bundle.one_time_pq);
  writer.Bytes(bundle.bundle_signature_ed25519);
  writer.Bytes(bundle.bundle_signature_mldsa65);
  writer.String(bundle.version);
  writer.String(bundle.cipher_suite);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<PrekeyBundle> DeserializePrekeyBundle(const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "prekey bundle payload");
  if (!size.ok()) {
    return Result<PrekeyBundle>::Err(size.error());
  }
  Reader reader(bytes);
  PrekeyBundle bundle;

  if (!reader.String(&bundle.user_id) || !reader.Bytes(&bundle.identity_sign_public_key) ||
      !reader.Bytes(&bundle.identity_mldsa_public_key) ||
      !reader.Bytes(&bundle.identity_dh_public_key) ||
      !ReadSignedPrekeyEc(&reader, &bundle.signed_prekey_ec) ||
      !ReadSignedPrekeyPq(&reader, &bundle.signed_prekey_pq) ||
      !ReadOneTimeEc(&reader, &bundle.one_time_ec) ||
      !ReadOneTimePq(&reader, &bundle.one_time_pq) ||
      !reader.Bytes(&bundle.bundle_signature_ed25519) ||
      !reader.Bytes(&bundle.bundle_signature_mldsa65) ||
      !reader.String(&bundle.version) ||
      !reader.String(&bundle.cipher_suite)) {
    return Result<PrekeyBundle>::Err("decode prekey bundle failed: " + reader.error());
  }

  if (!reader.Finished()) {
    return Result<PrekeyBundle>::Err("decode prekey bundle failed: trailing bytes");
  }

  return Result<PrekeyBundle>::Ok(std::move(bundle));
}

Result<std::vector<uint8_t>> SerializeEnvelope(const Envelope& envelope) {
  Writer writer;
  switch (envelope.type) {
    case EnvelopeType::kInitial:
      if (!envelope.initial.has_value()) {
        return Result<std::vector<uint8_t>>::Err(
            "serialize envelope failed: initial payload missing");
      }
      writer.U8(0);
      WriteInitialMessage(&writer, *envelope.initial);
      break;
    case EnvelopeType::kChat:
      if (!envelope.chat.has_value()) {
        return Result<std::vector<uint8_t>>::Err(
            "serialize envelope failed: chat payload missing");
      }
      writer.U8(1);
      WriteChatMessage(&writer, *envelope.chat);
      break;
  }

  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<Envelope> DeserializeEnvelope(const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "envelope payload");
  if (!size.ok()) {
    return Result<Envelope>::Err(size.error());
  }
  Reader reader(bytes);
  uint8_t tag = 0;
  if (!reader.U8(&tag)) {
    return Result<Envelope>::Err("decode envelope failed: " + reader.error());
  }

  Envelope envelope;
  if (tag == 0) {
    InitialMessage initial;
    if (!ReadInitialMessage(&reader, &initial)) {
      return Result<Envelope>::Err("decode initial message failed: " + reader.error());
    }
    envelope = Envelope::FromInitial(std::move(initial));
  } else if (tag == 1) {
    ChatMessage chat;
    if (!ReadChatMessage(&reader, &chat)) {
      return Result<Envelope>::Err("decode chat message failed: " + reader.error());
    }
    envelope = Envelope::FromChat(std::move(chat));
  } else {
    return Result<Envelope>::Err("decode envelope failed: unknown tag");
  }

  if (!reader.Finished()) {
    return Result<Envelope>::Err("decode envelope failed: trailing bytes");
  }

  return Result<Envelope>::Ok(std::move(envelope));
}

Result<std::vector<uint8_t>> SerializeEnvelopeVector(
    const std::vector<Envelope>& envelopes) {
  Writer writer;
  writer.U32(static_cast<uint32_t>(envelopes.size()));
  for (const auto& envelope : envelopes) {
    auto encoded = SerializeEnvelope(envelope);
    if (!encoded.ok()) {
      return Result<std::vector<uint8_t>>::Err(encoded.error());
    }
    writer.Bytes(encoded.value());
  }
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<std::vector<Envelope>> DeserializeEnvelopeVector(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "envelope vector payload");
  if (!size.ok()) {
    return Result<std::vector<Envelope>>::Err(size.error());
  }
  Reader reader(bytes);
  uint32_t count = 0;
  if (!reader.U32(&count)) {
    return Result<std::vector<Envelope>>::Err("decode envelope vector failed: " +
                                              reader.error());
  }

  if (!reader.LimitU32(count, kMaxEnvelopeVectorItems, "envelope vector count")) {
    return Result<std::vector<Envelope>>::Err(
        "decode envelope vector failed: " + reader.error());
  }

  std::vector<Envelope> out;
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    std::vector<uint8_t> encoded;
    if (!reader.Bytes(&encoded)) {
      return Result<std::vector<Envelope>>::Err(
          "decode envelope vector item failed: " + reader.error());
    }
    auto envelope = DeserializeEnvelope(encoded);
    if (!envelope.ok()) {
      return Result<std::vector<Envelope>>::Err(envelope.error());
    }
    out.push_back(envelope.take_value());
  }

  if (!reader.Finished()) {
    return Result<std::vector<Envelope>>::Err(
        "decode envelope vector failed: trailing bytes");
  }

  return Result<std::vector<Envelope>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeInboxEnvelopeVector(
    const std::vector<InboxEnvelope>& envelopes) {
  Writer writer;
  writer.U32(static_cast<uint32_t>(envelopes.size()));
  for (const auto& item : envelopes) {
    auto encoded = SerializeEnvelope(item.envelope);
    if (!encoded.ok()) {
      return Result<std::vector<uint8_t>>::Err(encoded.error());
    }
    writer.U64(item.inbox_id);
    writer.Bytes(encoded.value());
  }
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<std::vector<InboxEnvelope>> DeserializeInboxEnvelopeVector(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "inbox envelope vector payload");
  if (!size.ok()) {
    return Result<std::vector<InboxEnvelope>>::Err(size.error());
  }
  Reader reader(bytes);
  uint32_t count = 0;
  if (!reader.U32(&count)) {
    return Result<std::vector<InboxEnvelope>>::Err(
        "decode inbox envelope vector failed: " + reader.error());
  }

  if (!reader.LimitU32(count, kMaxEnvelopeVectorItems, "inbox envelope vector count")) {
    return Result<std::vector<InboxEnvelope>>::Err(
        "decode inbox envelope vector failed: " + reader.error());
  }

  std::vector<InboxEnvelope> out;
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    InboxEnvelope item;
    std::vector<uint8_t> encoded;
    if (!reader.U64(&item.inbox_id) || !reader.Bytes(&encoded)) {
      return Result<std::vector<InboxEnvelope>>::Err(
          "decode inbox envelope vector item failed: " + reader.error());
    }
    auto envelope = DeserializeEnvelope(encoded);
    if (!envelope.ok()) {
      return Result<std::vector<InboxEnvelope>>::Err(envelope.error());
    }
    item.envelope = envelope.take_value();
    out.push_back(std::move(item));
  }

  if (!reader.Finished()) {
    return Result<std::vector<InboxEnvelope>>::Err(
        "decode inbox envelope vector failed: trailing bytes");
  }

  return Result<std::vector<InboxEnvelope>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeString(const std::string& value) {
  Writer writer;
  writer.String(value);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<std::string> DeserializeString(const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "string payload");
  if (!size.ok()) {
    return Result<std::string>::Err(size.error());
  }
  Reader reader(bytes);
  std::string out;
  if (!reader.String(&out)) {
    return Result<std::string>::Err("decode string failed: " + reader.error());
  }
  if (!reader.Finished()) {
    return Result<std::string>::Err("decode string failed: trailing bytes");
  }
  return Result<std::string>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeEnqueueRequest(
    const EnqueueRequest& request) {
  auto envelope = SerializeEnvelope(request.envelope);
  if (!envelope.ok()) {
    return Result<std::vector<uint8_t>>::Err(envelope.error());
  }

  Writer writer;
  writer.String(request.user_id);
  writer.Bytes(envelope.value());
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<EnqueueRequest> DeserializeEnqueueRequest(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "enqueue request payload");
  if (!size.ok()) {
    return Result<EnqueueRequest>::Err(size.error());
  }
  Reader reader(bytes);
  EnqueueRequest out;
  std::vector<uint8_t> envelope_bytes;

  if (!reader.String(&out.user_id) || !reader.Bytes(&envelope_bytes)) {
    return Result<EnqueueRequest>::Err("decode enqueue request failed: " +
                                       reader.error());
  }

  if (!reader.Finished()) {
    return Result<EnqueueRequest>::Err(
        "decode enqueue request failed: trailing bytes");
  }

  auto envelope = DeserializeEnvelope(envelope_bytes);
  if (!envelope.ok()) {
    return Result<EnqueueRequest>::Err(envelope.error());
  }
  out.envelope = envelope.take_value();
  return Result<EnqueueRequest>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeDrainInboxRequest(
    const DrainInboxRequest& request) {
  Writer writer;
  writer.String(request.user_id);
  writer.U8(request.ack_up_to_inbox_id.has_value() ? 1 : 0);
  if (request.ack_up_to_inbox_id.has_value()) {
    writer.U64(*request.ack_up_to_inbox_id);
  }
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<DrainInboxRequest> DeserializeDrainInboxRequest(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "drain inbox request payload");
  if (!size.ok()) {
    return Result<DrainInboxRequest>::Err(size.error());
  }
  Reader reader(bytes);
  DrainInboxRequest out;
  uint8_t has_ack = 0;
  if (!reader.String(&out.user_id) || !reader.U8(&has_ack)) {
    return Result<DrainInboxRequest>::Err("decode drain inbox request failed: " +
                                          reader.error());
  }
  if (has_ack == 1) {
    uint64_t id = 0;
    if (!reader.U64(&id)) {
      return Result<DrainInboxRequest>::Err("decode drain inbox request failed: " +
                                            reader.error());
    }
    out.ack_up_to_inbox_id = id;
  } else if (has_ack != 0) {
    return Result<DrainInboxRequest>::Err(
        "decode drain inbox request failed: invalid ack tag");
  }

  if (!reader.Finished()) {
    return Result<DrainInboxRequest>::Err(
        "decode drain inbox request failed: trailing bytes");
  }
  return Result<DrainInboxRequest>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeRegisterRequest(
    const RegisterRequest& request) {
  Writer writer;
  writer.String(request.user_id);
  writer.Bytes(request.transport_auth_public_key);
  writer.String(request.registration_token);
  writer.Bytes(request.proof_signature_mldsa65);
  writer.OptionalBytes(request.rotation_signature_mldsa65);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<RegisterRequest> DeserializeRegisterRequest(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "register request payload");
  if (!size.ok()) {
    return Result<RegisterRequest>::Err(size.error());
  }
  Reader reader(bytes);
  RegisterRequest out;
  if (!reader.String(&out.user_id) || !reader.Bytes(&out.transport_auth_public_key) ||
      !reader.String(&out.registration_token) ||
      !reader.Bytes(&out.proof_signature_mldsa65) ||
      !reader.OptionalBytes(&out.rotation_signature_mldsa65)) {
    return Result<RegisterRequest>::Err("decode register request failed: " +
                                        reader.error());
  }
  if (!reader.Finished()) {
    return Result<RegisterRequest>::Err(
        "decode register request failed: trailing bytes");
  }
  return Result<RegisterRequest>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeAuthBeginRequest(
    const AuthBeginRequest& request) {
  Writer writer;
  writer.String(request.user_id);
  writer.Bytes(request.client_nonce);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<AuthBeginRequest> DeserializeAuthBeginRequest(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "auth begin request payload");
  if (!size.ok()) {
    return Result<AuthBeginRequest>::Err(size.error());
  }
  Reader reader(bytes);
  AuthBeginRequest out;
  if (!reader.String(&out.user_id) || !reader.Bytes(&out.client_nonce)) {
    return Result<AuthBeginRequest>::Err("decode auth begin request failed: " +
                                         reader.error());
  }
  if (!reader.Finished()) {
    return Result<AuthBeginRequest>::Err(
        "decode auth begin request failed: trailing bytes");
  }
  return Result<AuthBeginRequest>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeAuthBeginResponse(
    const AuthBeginResponse& response) {
  Writer writer;
  writer.String(response.challenge_id);
  writer.Bytes(response.server_nonce);
  writer.U64(response.expires_at_unix);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<AuthBeginResponse> DeserializeAuthBeginResponse(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "auth begin response payload");
  if (!size.ok()) {
    return Result<AuthBeginResponse>::Err(size.error());
  }
  Reader reader(bytes);
  AuthBeginResponse out;
  if (!reader.String(&out.challenge_id) || !reader.Bytes(&out.server_nonce) ||
      !reader.U64(&out.expires_at_unix)) {
    return Result<AuthBeginResponse>::Err("decode auth begin response failed: " +
                                          reader.error());
  }
  if (!reader.Finished()) {
    return Result<AuthBeginResponse>::Err(
        "decode auth begin response failed: trailing bytes");
  }
  return Result<AuthBeginResponse>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeAuthFinishRequest(
    const AuthFinishRequest& request) {
  Writer writer;
  writer.String(request.user_id);
  writer.String(request.challenge_id);
  writer.Bytes(request.client_nonce);
  writer.Bytes(request.server_nonce);
  writer.U64(request.expires_at_unix);
  writer.Bytes(request.signature_mldsa65);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<AuthFinishRequest> DeserializeAuthFinishRequest(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "auth finish request payload");
  if (!size.ok()) {
    return Result<AuthFinishRequest>::Err(size.error());
  }
  Reader reader(bytes);
  AuthFinishRequest out;
  if (!reader.String(&out.user_id) || !reader.String(&out.challenge_id) ||
      !reader.Bytes(&out.client_nonce) || !reader.Bytes(&out.server_nonce) ||
      !reader.U64(&out.expires_at_unix) || !reader.Bytes(&out.signature_mldsa65)) {
    return Result<AuthFinishRequest>::Err("decode auth finish request failed: " +
                                          reader.error());
  }
  if (!reader.Finished()) {
    return Result<AuthFinishRequest>::Err(
        "decode auth finish request failed: trailing bytes");
  }
  return Result<AuthFinishRequest>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeAuthFinishResponse(
    const AuthFinishResponse& response) {
  Writer writer;
  writer.Bytes(response.session_token);
  writer.U64(response.expires_at_unix);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<AuthFinishResponse> DeserializeAuthFinishResponse(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "auth finish response payload");
  if (!size.ok()) {
    return Result<AuthFinishResponse>::Err(size.error());
  }
  Reader reader(bytes);
  AuthFinishResponse out;
  if (!reader.Bytes(&out.session_token) || !reader.U64(&out.expires_at_unix)) {
    return Result<AuthFinishResponse>::Err("decode auth finish response failed: " +
                                           reader.error());
  }
  if (!reader.Finished()) {
    return Result<AuthFinishResponse>::Err(
        "decode auth finish response failed: trailing bytes");
  }
  return Result<AuthFinishResponse>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> SerializeAuthenticatedPayload(
    const AuthenticatedPayload& payload) {
  Writer writer;
  writer.Bytes(payload.session_token);
  writer.Bytes(payload.payload);
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<AuthenticatedPayload> DeserializeAuthenticatedPayload(
    const std::vector<uint8_t>& bytes) {
  auto size = ValidateInputSize(bytes, "authenticated payload");
  if (!size.ok()) {
    return Result<AuthenticatedPayload>::Err(size.error());
  }
  Reader reader(bytes);
  AuthenticatedPayload out;
  if (!reader.Bytes(&out.session_token) || !reader.Bytes(&out.payload)) {
    return Result<AuthenticatedPayload>::Err(
        "decode authenticated payload failed: " + reader.error());
  }
  if (!reader.Finished()) {
    return Result<AuthenticatedPayload>::Err(
        "decode authenticated payload failed: trailing bytes");
  }
  return Result<AuthenticatedPayload>::Ok(std::move(out));
}

}  // namespace pqchat::protocol
