#include "pqchat/client/client.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <optional>
#include <sstream>

#include <openssl/rand.h>

#include "pqchat/crypto/aead.h"
#include "pqchat/crypto/ed25519.h"
#include "pqchat/crypto/hash.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/crypto/mlkem.h"
#include "pqchat/crypto/x25519.h"

namespace pqchat::client {
namespace {

std::vector<uint8_t> U64Bytes(uint64_t value) {
  std::vector<uint8_t> out(8);
  for (int i = 7; i >= 0; --i) {
    out[7 - i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
  }
  return out;
}

Result<std::vector<uint8_t>> DeriveKeyMaterial(const std::vector<uint8_t>& ikm,
                                               const std::vector<uint8_t>& salt,
                                               const std::string& label,
                                               const std::vector<uint8_t>& context,
                                               size_t out_len) {
  auto info = crypto::Concat({crypto::ToBytes(label), context});
  return crypto::HkdfSha256(ikm, salt, info, out_len);
}

Result<std::array<std::vector<uint8_t>, 3>> DeriveHandshakeKeys(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& transcript_hash,
    bool initiator) {
  auto material_result =
      DeriveKeyMaterial(ikm,
                        {},
                        "pqchat_handshake_keys_v1",
                        transcript_hash,
                        96);
  if (!material_result.ok()) {
    return Result<std::array<std::vector<uint8_t>, 3>>::Err(material_result.error());
  }

  auto material = material_result.take_value();
  std::array<std::vector<uint8_t>, 3> out;
  out[0] = std::vector<uint8_t>(material.begin(), material.begin() + 32);  // root

  std::vector<uint8_t> c1(material.begin() + 32, material.begin() + 64);
  std::vector<uint8_t> c2(material.begin() + 64, material.begin() + 96);

  if (initiator) {
    out[1] = std::move(c1);  // send
    out[2] = std::move(c2);  // recv
  } else {
    out[1] = std::move(c2);  // send
    out[2] = std::move(c1);  // recv
  }

  return Result<std::array<std::vector<uint8_t>, 3>>::Ok(std::move(out));
}

Result<std::array<std::vector<uint8_t>, 2>> DeriveMessageKeyAndNextChain(
    const crypto::SecureBuffer& chain_key,
    uint64_t counter) {
  auto material = DeriveKeyMaterial(chain_key.bytes(),
                                    {},
                                    "pqchat_chain_step_v1",
                                    U64Bytes(counter),
                                    64);
  if (!material.ok()) {
    return Result<std::array<std::vector<uint8_t>, 2>>::Err(material.error());
  }

  auto bytes = material.take_value();
  std::array<std::vector<uint8_t>, 2> out;
  out[0] = std::vector<uint8_t>(bytes.begin(), bytes.begin() + 32);      // msg key
  out[1] = std::vector<uint8_t>(bytes.begin() + 32, bytes.begin() + 64); // next ck
  return Result<std::array<std::vector<uint8_t>, 2>>::Ok(std::move(out));
}

Result<std::array<std::vector<uint8_t>, 2>> DeriveRatchetRootAndChain(
    const std::vector<uint8_t>& dh,
    const crypto::SecureBuffer& root_key) {
  auto material = DeriveKeyMaterial(dh,
                                    root_key.bytes(),
                                    "pqchat_ratchet_step_v1",
                                    {},
                                    64);
  if (!material.ok()) {
    return Result<std::array<std::vector<uint8_t>, 2>>::Err(material.error());
  }

  auto bytes = material.take_value();
  std::array<std::vector<uint8_t>, 2> out;
  out[0] = std::vector<uint8_t>(bytes.begin(), bytes.begin() + 32);      // new chain
  out[1] = std::vector<uint8_t>(bytes.begin() + 32, bytes.begin() + 64); // new root
  return Result<std::array<std::vector<uint8_t>, 2>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> EncryptChainStep(crypto::SecureBuffer* chain_key,
                                              uint64_t counter,
                                              const std::vector<uint8_t>& nonce,
                                              const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& ad) {
  auto key_result = DeriveMessageKeyAndNextChain(*chain_key, counter);
  if (!key_result.ok()) {
    return Result<std::vector<uint8_t>>::Err(key_result.error());
  }
  auto keys = key_result.take_value();

  auto ciphertext = crypto::AeadChaCha20Poly1305::Seal(keys[0], nonce, plaintext, ad);
  if (!ciphertext.ok()) {
    return Result<std::vector<uint8_t>>::Err(ciphertext.error());
  }

  *chain_key = crypto::SecureBuffer(std::move(keys[1]));
  return Result<std::vector<uint8_t>>::Ok(ciphertext.take_value());
}

Result<std::vector<uint8_t>> DecryptChainStep(crypto::SecureBuffer* chain_key,
                                              uint64_t counter,
                                              const std::vector<uint8_t>& nonce,
                                              const std::vector<uint8_t>& ciphertext,
                                              const std::vector<uint8_t>& ad) {
  auto key_result = DeriveMessageKeyAndNextChain(*chain_key, counter);
  if (!key_result.ok()) {
    return Result<std::vector<uint8_t>>::Err(key_result.error());
  }
  auto keys = key_result.take_value();

  auto plaintext = crypto::AeadChaCha20Poly1305::Open(keys[0], nonce, ciphertext, ad);
  if (!plaintext.ok()) {
    return Result<std::vector<uint8_t>>::Err(plaintext.error());
  }

  *chain_key = crypto::SecureBuffer(std::move(keys[1]));
  return Result<std::vector<uint8_t>>::Ok(plaintext.take_value());
}

crypto::X25519KeyPair CloneX25519KeyPair(const crypto::X25519KeyPair& source) {
  crypto::X25519KeyPair out{
      crypto::SecureBuffer(std::vector<uint8_t>(source.private_key.bytes().begin(),
                                                source.private_key.bytes().end())),
      source.public_key};
  return out;
}

}  // namespace

Result<Client> Client::Create(std::string user_id) {
  Client client;
  client.user_id_ = std::move(user_id);

  auto id_sign = crypto::Ed25519::GenerateKeyPair();
  if (!id_sign.ok()) {
    return Result<Client>::Err("identity Ed25519 keygen failed: " + id_sign.error());
  }
  client.identity_sign_key_ = id_sign.take_value();

  auto id_mldsa = crypto::MlDsa65::GenerateKeyPair();
  if (!id_mldsa.ok()) {
    return Result<Client>::Err("identity ML-DSA keygen failed: " + id_mldsa.error());
  }
  client.identity_mldsa_key_ = id_mldsa.take_value();

  auto id_dh = crypto::X25519::GenerateKeyPair();
  if (!id_dh.ok()) {
    return Result<Client>::Err("identity X25519 keygen failed: " + id_dh.error());
  }
  client.identity_dh_key_ = id_dh.take_value();

  auto spk_ec = crypto::X25519::GenerateKeyPair();
  if (!spk_ec.ok()) {
    return Result<Client>::Err("signed prekey EC keygen failed: " + spk_ec.error());
  }
  client.signed_prekey_ec_private_ = spk_ec.take_value();
  client.signed_prekey_ec_public_.id = 1;
  client.signed_prekey_ec_public_.public_key = client.signed_prekey_ec_private_.public_key;

  auto spk_ec_sig_input = protocol::BuildEcPrekeySignInput(
      client.signed_prekey_ec_public_.id,
      client.signed_prekey_ec_public_.public_key);
  auto spk_ec_sig =
      crypto::Ed25519::Sign(client.identity_sign_key_.private_key, spk_ec_sig_input);
  if (!spk_ec_sig.ok()) {
    return Result<Client>::Err("signed prekey EC signature failed: " + spk_ec_sig.error());
  }
  client.signed_prekey_ec_public_.signature_ed25519 = spk_ec_sig.take_value();

  auto spk_ec_sig_mldsa =
      crypto::MlDsa65::Sign(client.identity_mldsa_key_.private_key.get(), spk_ec_sig_input);
  if (!spk_ec_sig_mldsa.ok()) {
    return Result<Client>::Err("signed prekey EC ML-DSA signature failed: " +
                               spk_ec_sig_mldsa.error());
  }
  client.signed_prekey_ec_public_.signature_mldsa65 = spk_ec_sig_mldsa.take_value();

  auto spk_pq = crypto::MlKem768::GenerateKeyPair();
  if (!spk_pq.ok()) {
    return Result<Client>::Err("signed prekey PQ keygen failed: " + spk_pq.error());
  }
  client.signed_prekey_pq_private_ = spk_pq.take_value();
  client.signed_prekey_pq_public_.id = 1;
  client.signed_prekey_pq_public_.public_key = client.signed_prekey_pq_private_.public_key;

  auto spk_pq_sig_input = protocol::BuildPqPrekeySignInput(
      client.signed_prekey_pq_public_.id,
      client.signed_prekey_pq_public_.public_key);
  auto spk_pq_sig =
      crypto::Ed25519::Sign(client.identity_sign_key_.private_key, spk_pq_sig_input);
  if (!spk_pq_sig.ok()) {
    return Result<Client>::Err("signed prekey PQ signature failed: " + spk_pq_sig.error());
  }
  client.signed_prekey_pq_public_.signature_ed25519 = spk_pq_sig.take_value();

  auto spk_pq_sig_mldsa =
      crypto::MlDsa65::Sign(client.identity_mldsa_key_.private_key.get(), spk_pq_sig_input);
  if (!spk_pq_sig_mldsa.ok()) {
    return Result<Client>::Err("signed prekey PQ ML-DSA signature failed: " +
                               spk_pq_sig_mldsa.error());
  }
  client.signed_prekey_pq_public_.signature_mldsa65 = spk_pq_sig_mldsa.take_value();

  auto opk_ec_private = crypto::X25519::GenerateKeyPair();
  if (!opk_ec_private.ok()) {
    return Result<Client>::Err("one-time EC keygen failed: " + opk_ec_private.error());
  }
  OneTimeEc one_time_ec;
  one_time_ec.public_part.id = 1001;
  one_time_ec.public_part.public_key = opk_ec_private.value().public_key;
  one_time_ec.private_part = opk_ec_private.take_value();
  client.one_time_ec_ = std::move(one_time_ec);

  auto opk_pq_private = crypto::MlKem768::GenerateKeyPair();
  if (!opk_pq_private.ok()) {
    return Result<Client>::Err("one-time PQ keygen failed: " + opk_pq_private.error());
  }
  OneTimePq one_time_pq;
  one_time_pq.public_part.id = 1001;
  one_time_pq.public_part.public_key = opk_pq_private.value().public_key;
  one_time_pq.private_part = opk_pq_private.take_value();
  client.one_time_pq_ = std::move(one_time_pq);

  return Result<Client>::Ok(std::move(client));
}

protocol::PrekeyBundle Client::BuildPrekeyBundle() const {
  protocol::PrekeyBundle bundle;
  bundle.user_id = user_id_;
  bundle.identity_sign_public_key = identity_sign_key_.public_key;
  bundle.identity_mldsa_public_key = identity_mldsa_key_.public_key;
  bundle.identity_dh_public_key = identity_dh_key_.public_key;
  bundle.signed_prekey_ec = signed_prekey_ec_public_;
  bundle.signed_prekey_pq = signed_prekey_pq_public_;

  if (one_time_ec_.has_value()) {
    bundle.one_time_ec = one_time_ec_->public_part;
  }

  if (one_time_pq_.has_value()) {
    bundle.one_time_pq = one_time_pq_->public_part;
  }

  return bundle;
}

Result<std::vector<uint8_t>> Client::SignTransportAuth(
    const std::vector<uint8_t>& message) const {
  return crypto::MlDsa65::Sign(identity_mldsa_key_.private_key.get(), message);
}

Result<void> Client::PublishPrekeys(server::IServerApi* server) {
  if (server == nullptr) {
    return Result<void>::Err("server is null");
  }
  return server->PublishBundle(BuildPrekeyBundle());
}

Result<void> Client::InitiateSession(server::IServerApi* server,
                                     const std::string& peer_user,
                                     const std::string& initial_plaintext) {
  if (server == nullptr) {
    return Result<void>::Err("server is null");
  }

  auto bundle_result = server->AcquireBundleForSession(peer_user);
  if (!bundle_result.ok()) {
    return Result<void>::Err("failed to fetch peer bundle: " + bundle_result.error());
  }

  const auto& bundle = bundle_result.value();
  auto verify = protocol::VerifyPrekeyBundleSignatures(bundle);
  if (!verify.ok()) {
    return Result<void>::Err("peer bundle verification failed: " + verify.error());
  }

  auto session_id_result = NewSessionId();
  if (!session_id_result.ok()) {
    return Result<void>::Err(session_id_result.error());
  }

  auto eph_result = crypto::X25519::GenerateKeyPair();
  if (!eph_result.ok()) {
    return Result<void>::Err("ephemeral keygen failed: " + eph_result.error());
  }
  auto eph = eph_result.take_value();
  const auto eph_public = eph.public_key;

  auto dh1 = crypto::X25519::SharedSecret(identity_dh_key_.private_key,
                                          bundle.signed_prekey_ec.public_key);
  if (!dh1.ok()) {
    return Result<void>::Err("dh1 failed: " + dh1.error());
  }

  auto dh2 = crypto::X25519::SharedSecret(eph.private_key,
                                          bundle.identity_dh_public_key);
  if (!dh2.ok()) {
    return Result<void>::Err("dh2 failed: " + dh2.error());
  }

  auto dh3 = crypto::X25519::SharedSecret(eph.private_key,
                                          bundle.signed_prekey_ec.public_key);
  if (!dh3.ok()) {
    return Result<void>::Err("dh3 failed: " + dh3.error());
  }

  std::optional<std::vector<uint8_t>> dh4;
  if (bundle.one_time_ec.has_value()) {
    auto dh4_result =
        crypto::X25519::SharedSecret(eph.private_key, bundle.one_time_ec->public_key);
    if (!dh4_result.ok()) {
      return Result<void>::Err("dh4 failed: " + dh4_result.error());
    }
    dh4 = dh4_result.take_value();
  }

  auto kem_spk = crypto::MlKem768::Encapsulate(bundle.signed_prekey_pq.public_key);
  if (!kem_spk.ok()) {
    return Result<void>::Err("KEM encaps to signed prekey failed: " + kem_spk.error());
  }

  std::optional<crypto::MlKemEncapResult> kem_opk;
  if (bundle.one_time_pq.has_value()) {
    auto kem_opk_result = crypto::MlKem768::Encapsulate(bundle.one_time_pq->public_key);
    if (!kem_opk_result.ok()) {
      return Result<void>::Err("KEM encaps to one-time prekey failed: " +
                               kem_opk_result.error());
    }
    kem_opk = kem_opk_result.take_value();
  }

  protocol::InitialTranscriptFields transcript_fields;
  transcript_fields.from_user = user_id_;
  transcript_fields.to_user = peer_user;
  transcript_fields.initiator_identity_sign_public_key = identity_sign_key_.public_key;
  transcript_fields.initiator_identity_mldsa_public_key = identity_mldsa_key_.public_key;
  transcript_fields.initiator_identity_dh_public_key = identity_dh_key_.public_key;
  transcript_fields.responder_identity_sign_public_key = bundle.identity_sign_public_key;
  transcript_fields.responder_identity_mldsa_public_key = bundle.identity_mldsa_public_key;
  transcript_fields.responder_identity_dh_public_key = bundle.identity_dh_public_key;
  transcript_fields.initiator_ephemeral_ec_public_key = eph_public;
  transcript_fields.selected_prekeys.signed_prekey_ec_id = bundle.signed_prekey_ec.id;
  transcript_fields.selected_prekeys.signed_prekey_pq_id = bundle.signed_prekey_pq.id;

  if (bundle.one_time_ec.has_value()) {
    transcript_fields.selected_prekeys.one_time_ec_id = bundle.one_time_ec->id;
  }
  if (bundle.one_time_pq.has_value()) {
    transcript_fields.selected_prekeys.one_time_pq_id = bundle.one_time_pq->id;
  }

  transcript_fields.kem_ciphertext_signed_pq = kem_spk.value().ciphertext;
  if (kem_opk.has_value()) {
    transcript_fields.kem_ciphertext_one_time_pq = kem_opk->ciphertext;
  }

  auto transcript_hash = protocol::ComputeInitialTranscriptHash(transcript_fields);
  if (!transcript_hash.ok()) {
    return Result<void>::Err("transcript hash failed: " + transcript_hash.error());
  }

  auto handshake_sig =
      crypto::Ed25519::Sign(identity_sign_key_.private_key, transcript_hash.value());
  if (!handshake_sig.ok()) {
    return Result<void>::Err("handshake ed25519 signature failed: " + handshake_sig.error());
  }

  auto handshake_sig_mldsa =
      crypto::MlDsa65::Sign(identity_mldsa_key_.private_key.get(), transcript_hash.value());
  if (!handshake_sig_mldsa.ok()) {
    return Result<void>::Err("handshake mldsa signature failed: " +
                             handshake_sig_mldsa.error());
  }

  std::vector<std::vector<uint8_t>> ikm_parts = {
      dh1.value(), dh2.value(), dh3.value(), kem_spk.value().shared_secret};
  if (dh4.has_value()) {
    ikm_parts.push_back(*dh4);
  }
  if (kem_opk.has_value()) {
    ikm_parts.push_back(kem_opk->shared_secret);
  }

  auto handshake_keys =
      DeriveHandshakeKeys(crypto::Concat(ikm_parts), transcript_hash.value(), true);
  if (!handshake_keys.ok()) {
    return Result<void>::Err("handshake key schedule failed: " + handshake_keys.error());
  }

  SessionState state;
  state.session_id = session_id_result.take_value();
  state.peer_user = peer_user;
  state.is_initiator = true;
  state.root_key = crypto::SecureBuffer(std::move(handshake_keys.value()[0]));
  state.send_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[1]));
  state.recv_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[2]));
  state.local_ratchet_key = std::move(eph);
  state.remote_ratchet_public = bundle.signed_prekey_ec.public_key;

  protocol::InitialMessage initial_message;
  initial_message.session_id = state.session_id;
  initial_message.from_user = user_id_;
  initial_message.to_user = peer_user;
  initial_message.initiator_identity_sign_public_key = identity_sign_key_.public_key;
  initial_message.initiator_identity_mldsa_public_key = identity_mldsa_key_.public_key;
  initial_message.initiator_identity_dh_public_key = identity_dh_key_.public_key;
  initial_message.initiator_ephemeral_ec_public_key = eph_public;
  initial_message.selected_prekeys = transcript_fields.selected_prekeys;
  initial_message.kem_ciphertext_signed_pq = kem_spk.value().ciphertext;
  if (kem_opk.has_value()) {
    initial_message.kem_ciphertext_one_time_pq = kem_opk->ciphertext;
  }
  initial_message.transcript_hash = transcript_hash.value();
  initial_message.handshake_signature_ed25519 = handshake_sig.take_value();
  initial_message.handshake_signature_mldsa65 = handshake_sig_mldsa.take_value();

  initial_message.initial_nonce = crypto::NonceFromCounter(state.send_counter);
  auto encrypted_initial = EncryptChainStep(&state.send_chain_key,
                                            state.send_counter,
                                            initial_message.initial_nonce,
                                            crypto::ToBytes(initial_plaintext),
                                            transcript_hash.value());
  if (!encrypted_initial.ok()) {
    return Result<void>::Err("encrypt initial payload failed: " + encrypted_initial.error());
  }
  initial_message.initial_ciphertext = encrypted_initial.take_value();
  state.send_counter++;

  sessions_by_peer_[peer_user] = std::move(state);

  return server->EnqueueEnvelope(peer_user,
                                 protocol::Envelope::FromInitial(std::move(initial_message)));
}

Result<void> Client::SendMessage(server::IServerApi* server,
                                 const std::string& peer_user,
                                 const std::string& plaintext) {
  if (server == nullptr) {
    return Result<void>::Err("server is null");
  }

  auto session_it = sessions_by_peer_.find(peer_user);
  if (session_it == sessions_by_peer_.end()) {
    return Result<void>::Err("no active session with peer");
  }
  auto& session = session_it->second;

  protocol::ChatMessage message;
  message.session_id = session.session_id;
  message.from_user = user_id_;
  message.to_user = peer_user;

  if (session.send_counter > 0 && session.send_counter % kRatchetInterval == 0) {
    auto new_ratchet_result = crypto::X25519::GenerateKeyPair();
    if (!new_ratchet_result.ok()) {
      return Result<void>::Err("ratchet keygen failed: " + new_ratchet_result.error());
    }

    auto dh = crypto::X25519::SharedSecret(new_ratchet_result.value().private_key,
                                           session.remote_ratchet_public);
    if (!dh.ok()) {
      return Result<void>::Err("ratchet DH failed: " + dh.error());
    }

    auto mixed = DeriveRatchetRootAndChain(dh.value(), session.root_key);
    if (!mixed.ok()) {
      return Result<void>::Err("ratchet KDF failed: " + mixed.error());
    }

    session.local_ratchet_key = new_ratchet_result.take_value();
    session.send_chain_key = crypto::SecureBuffer(std::move(mixed.value()[0]));
    session.root_key = crypto::SecureBuffer(std::move(mixed.value()[1]));

    message.header.sender_ratchet_public_key = session.local_ratchet_key.public_key;
    message.header.previous_chain_length = session.previous_send_chain_length;
    session.previous_send_chain_length = session.send_counter;
    session.send_counter = 0;
    message.header.flags |= 0x1;
  }

  message.header.message_number = session.send_counter;
  message.nonce = crypto::NonceFromCounter(session.send_counter);

  auto ad = protocol::BuildChatAssociatedData(message);
  if (!ad.ok()) {
    return Result<void>::Err("chat AD failed: " + ad.error());
  }

  auto ciphertext = EncryptChainStep(&session.send_chain_key,
                                     session.send_counter,
                                     message.nonce,
                                     crypto::ToBytes(plaintext),
                                     ad.value());
  if (!ciphertext.ok()) {
    return Result<void>::Err("message encryption failed: " + ciphertext.error());
  }
  message.ciphertext = ciphertext.take_value();
  session.send_counter++;

  return server->EnqueueEnvelope(peer_user, protocol::Envelope::FromChat(std::move(message)));
}

Result<std::vector<std::string>> Client::ProcessInbox(server::IServerApi* server) {
  if (server == nullptr) {
    return Result<std::vector<std::string>>::Err("server is null");
  }

  auto envelopes_result = server->DrainInbox(user_id_);
  if (!envelopes_result.ok()) {
    return Result<std::vector<std::string>>::Err("drain inbox failed: " +
                                                 envelopes_result.error());
  }
  auto envelopes = envelopes_result.take_value();
  std::vector<std::string> plaintexts;

  for (const auto& envelope : envelopes) {
    Result<void> status = Result<void>::Ok();
    if (envelope.type == protocol::EnvelopeType::kInitial && envelope.initial.has_value()) {
      status = HandleInitialMessage(*envelope.initial, &plaintexts);
    } else if (envelope.type == protocol::EnvelopeType::kChat && envelope.chat.has_value()) {
      status = HandleChatMessage(*envelope.chat, &plaintexts);
    } else {
      status = Result<void>::Err("invalid envelope");
    }

    if (!status.ok()) {
      return Result<std::vector<std::string>>::Err(status.error());
    }
  }

  return Result<std::vector<std::string>>::Ok(std::move(plaintexts));
}

Result<void> Client::HandleInitialMessage(const protocol::InitialMessage& message,
                                          std::vector<std::string>* plaintext_out) {
  if (message.to_user != user_id_) {
    return Result<void>::Err("initial message recipient mismatch");
  }

  if (message.selected_prekeys.signed_prekey_ec_id != signed_prekey_ec_public_.id ||
      message.selected_prekeys.signed_prekey_pq_id != signed_prekey_pq_public_.id) {
    return Result<void>::Err("initial message selected unknown signed prekey id");
  }

  protocol::InitialTranscriptFields fields;
  fields.from_user = message.from_user;
  fields.to_user = message.to_user;
  fields.initiator_identity_sign_public_key = message.initiator_identity_sign_public_key;
  fields.initiator_identity_mldsa_public_key = message.initiator_identity_mldsa_public_key;
  fields.initiator_identity_dh_public_key = message.initiator_identity_dh_public_key;
  fields.responder_identity_sign_public_key = identity_sign_key_.public_key;
  fields.responder_identity_mldsa_public_key = identity_mldsa_key_.public_key;
  fields.responder_identity_dh_public_key = identity_dh_key_.public_key;
  fields.initiator_ephemeral_ec_public_key = message.initiator_ephemeral_ec_public_key;
  fields.selected_prekeys = message.selected_prekeys;
  fields.kem_ciphertext_signed_pq = message.kem_ciphertext_signed_pq;
  fields.kem_ciphertext_one_time_pq = message.kem_ciphertext_one_time_pq;

  auto transcript_hash = protocol::ComputeInitialTranscriptHash(fields);
  if (!transcript_hash.ok()) {
    return Result<void>::Err("transcript hash failed: " + transcript_hash.error());
  }
  if (transcript_hash.value() != message.transcript_hash) {
    return Result<void>::Err("transcript hash mismatch");
  }

  auto sig_verify = crypto::Ed25519::Verify(message.initiator_identity_sign_public_key,
                                            message.transcript_hash,
                                            message.handshake_signature_ed25519);
  if (!sig_verify.ok()) {
    return Result<void>::Err("handshake ed25519 signature invalid: " + sig_verify.error());
  }

  auto sig_verify_mldsa =
      crypto::MlDsa65::Verify(message.initiator_identity_mldsa_public_key,
                              message.transcript_hash,
                              message.handshake_signature_mldsa65);
  if (!sig_verify_mldsa.ok()) {
    return Result<void>::Err("handshake mldsa signature invalid: " +
                             sig_verify_mldsa.error());
  }

  auto dh1 = crypto::X25519::SharedSecret(signed_prekey_ec_private_.private_key,
                                          message.initiator_identity_dh_public_key);
  if (!dh1.ok()) {
    return Result<void>::Err("dh1 failed: " + dh1.error());
  }

  auto dh2 = crypto::X25519::SharedSecret(identity_dh_key_.private_key,
                                          message.initiator_ephemeral_ec_public_key);
  if (!dh2.ok()) {
    return Result<void>::Err("dh2 failed: " + dh2.error());
  }

  auto dh3 = crypto::X25519::SharedSecret(signed_prekey_ec_private_.private_key,
                                          message.initiator_ephemeral_ec_public_key);
  if (!dh3.ok()) {
    return Result<void>::Err("dh3 failed: " + dh3.error());
  }

  std::optional<std::vector<uint8_t>> dh4;
  if (message.selected_prekeys.one_time_ec_id.has_value()) {
    if (!one_time_ec_.has_value() ||
        one_time_ec_->public_part.id != *message.selected_prekeys.one_time_ec_id) {
      return Result<void>::Err("one-time EC key id unavailable");
    }
    auto dh4_result =
        crypto::X25519::SharedSecret(one_time_ec_->private_part.private_key,
                                     message.initiator_ephemeral_ec_public_key);
    if (!dh4_result.ok()) {
      return Result<void>::Err("dh4 failed: " + dh4_result.error());
    }
    dh4 = dh4_result.take_value();
    one_time_ec_.reset();
  }

  auto ss_spk_pq = crypto::MlKem768::Decapsulate(signed_prekey_pq_private_.private_key.get(),
                                                 message.kem_ciphertext_signed_pq);
  if (!ss_spk_pq.ok()) {
    return Result<void>::Err("decapsulate signed PQ prekey failed: " + ss_spk_pq.error());
  }

  std::optional<std::vector<uint8_t>> ss_opk_pq;
  if (message.selected_prekeys.one_time_pq_id.has_value()) {
    if (!one_time_pq_.has_value() ||
        one_time_pq_->public_part.id != *message.selected_prekeys.one_time_pq_id ||
        !message.kem_ciphertext_one_time_pq.has_value()) {
      return Result<void>::Err("one-time PQ key id unavailable");
    }

    auto ss_opk_pq_result = crypto::MlKem768::Decapsulate(
        one_time_pq_->private_part.private_key.get(),
        *message.kem_ciphertext_one_time_pq);
    if (!ss_opk_pq_result.ok()) {
      return Result<void>::Err("decapsulate one-time PQ prekey failed: " +
                               ss_opk_pq_result.error());
    }
    ss_opk_pq = ss_opk_pq_result.take_value();
    one_time_pq_.reset();
  }

  std::vector<std::vector<uint8_t>> ikm_parts = {
      dh1.value(), dh2.value(), dh3.value(), ss_spk_pq.value()};
  if (dh4.has_value()) {
    ikm_parts.push_back(*dh4);
  }
  if (ss_opk_pq.has_value()) {
    ikm_parts.push_back(*ss_opk_pq);
  }

  auto handshake_keys =
      DeriveHandshakeKeys(crypto::Concat(ikm_parts), message.transcript_hash, false);
  if (!handshake_keys.ok()) {
    return Result<void>::Err("handshake key schedule failed: " + handshake_keys.error());
  }

  SessionState state;
  state.session_id = message.session_id;
  state.peer_user = message.from_user;
  state.is_initiator = false;
  state.root_key = crypto::SecureBuffer(std::move(handshake_keys.value()[0]));
  state.send_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[1]));
  state.recv_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[2]));
  state.local_ratchet_key = CloneX25519KeyPair(signed_prekey_ec_private_);
  state.remote_ratchet_public = message.initiator_ephemeral_ec_public_key;

  auto plaintext = DecryptChainStep(&state.recv_chain_key,
                                    state.recv_counter,
                                    message.initial_nonce,
                                    message.initial_ciphertext,
                                    message.transcript_hash);
  if (!plaintext.ok()) {
    return Result<void>::Err("initial payload decrypt failed: " + plaintext.error());
  }

  state.recv_counter++;
  sessions_by_peer_[message.from_user] = std::move(state);

  plaintext_out->push_back(
      std::string(plaintext.value().begin(), plaintext.value().end()));
  return Result<void>::Ok();
}

Result<void> Client::HandleChatMessage(const protocol::ChatMessage& message,
                                       std::vector<std::string>* plaintext_out) {
  if (message.to_user != user_id_) {
    return Result<void>::Err("chat message recipient mismatch");
  }

  auto session_it = sessions_by_peer_.find(message.from_user);
  if (session_it == sessions_by_peer_.end()) {
    return Result<void>::Err("no session for incoming chat message");
  }

  auto& session = session_it->second;
  if (session.session_id != message.session_id) {
    return Result<void>::Err("session id mismatch");
  }

  if (message.header.sender_ratchet_public_key.has_value()) {
    const auto& new_remote = *message.header.sender_ratchet_public_key;
    if (new_remote != session.remote_ratchet_public) {
      auto dh = crypto::X25519::SharedSecret(session.local_ratchet_key.private_key,
                                             new_remote);
      if (!dh.ok()) {
        return Result<void>::Err("ratchet DH failed: " + dh.error());
      }

      auto mixed = DeriveRatchetRootAndChain(dh.value(), session.root_key);
      if (!mixed.ok()) {
        return Result<void>::Err("ratchet KDF failed: " + mixed.error());
      }

      session.recv_chain_key = crypto::SecureBuffer(std::move(mixed.value()[0]));
      session.root_key = crypto::SecureBuffer(std::move(mixed.value()[1]));
      session.remote_ratchet_public = new_remote;
      session.recv_counter = 0;
    }
  }

  if (message.header.message_number != session.recv_counter) {
    return Result<void>::Err("replay or out-of-order message rejected");
  }

  auto ad = protocol::BuildChatAssociatedData(message);
  if (!ad.ok()) {
    return Result<void>::Err("chat AD failed: " + ad.error());
  }

  auto plaintext = DecryptChainStep(&session.recv_chain_key,
                                    session.recv_counter,
                                    message.nonce,
                                    message.ciphertext,
                                    ad.value());
  if (!plaintext.ok()) {
    return Result<void>::Err("chat decrypt failed: " + plaintext.error());
  }

  session.recv_counter++;
  plaintext_out->push_back(
      std::string(plaintext.value().begin(), plaintext.value().end()));

  return Result<void>::Ok();
}

Result<std::string> Client::NewSessionId() {
  std::vector<uint8_t> random(16);
  if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
    return Result<std::string>::Err("RAND_bytes failed");
  }

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : random) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return Result<std::string>::Ok(oss.str());
}

}  // namespace pqchat::client
