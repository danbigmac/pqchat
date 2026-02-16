#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "pqchat/crypto/ed25519.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/crypto/mlkem.h"
#include "pqchat/crypto/secure_buffer.h"
#include "pqchat/crypto/x25519.h"
#include "pqchat/protocol/messages.h"
#include "pqchat/protocol/prekey_bundle.h"
#include "pqchat/server/server_api.h"
#include "pqchat/util/result.h"

namespace pqchat::client {

class Client {
 public:
  static Result<Client> Create(std::string user_id);

  [[nodiscard]] const std::string& user_id() const { return user_id_; }
  [[nodiscard]] const std::vector<uint8_t>& transport_auth_public_key() const {
    return identity_mldsa_key_.public_key;
  }

  Result<std::vector<uint8_t>> SignTransportAuth(
      const std::vector<uint8_t>& message) const;

  Result<std::string> GetPeerSafetyNumber(const std::string& peer_user) const;
  Result<void> VerifyPeerSafetyNumber(const std::string& peer_user,
                                      const std::string& expected_safety_number);

  [[nodiscard]] protocol::PrekeyBundle BuildPrekeyBundle() const;

  Result<void> PublishPrekeys(server::IServerApi* server);

  Result<void> InitiateSession(server::IServerApi* server,
                               const std::string& peer_user,
                               const std::string& initial_plaintext);

  Result<void> SendMessage(server::IServerApi* server,
                           const std::string& peer_user,
                           const std::string& plaintext);

  Result<std::vector<std::string>> ProcessInbox(server::IServerApi* server);

 private:
  struct SessionState {
    std::string session_id;
    std::string peer_user;
    bool is_initiator = false;

    crypto::SecureBuffer root_key;
    crypto::SecureBuffer send_chain_key;
    crypto::SecureBuffer recv_chain_key;

    uint64_t send_counter = 0;
    uint64_t recv_counter = 0;
    uint64_t previous_send_chain_length = 0;

    crypto::X25519KeyPair local_ratchet_key;
    std::vector<uint8_t> remote_ratchet_public;
  };

  struct OneTimeEc {
    protocol::OneTimePrekeyEc public_part;
    crypto::X25519KeyPair private_part;
  };

  struct OneTimePq {
    protocol::OneTimePrekeyPq public_part;
    crypto::MlKemKeyPair private_part;
  };

  struct PeerIdentity {
    std::vector<uint8_t> sign_public_key;
    std::vector<uint8_t> mldsa_public_key;
    std::vector<uint8_t> dh_public_key;
    bool verified = false;
  };

  Client() = default;

  Result<void> HandleInitialMessage(const protocol::InitialMessage& message,
                                    std::vector<std::string>* plaintext_out);

  Result<void> HandleChatMessage(const protocol::ChatMessage& message,
                                 std::vector<std::string>* plaintext_out);

  Result<void> VerifyOrRememberPeerIdentity(
      const std::string& peer_user,
      const std::vector<uint8_t>& sign_public_key,
      const std::vector<uint8_t>& mldsa_public_key,
      const std::vector<uint8_t>& dh_public_key);
  Result<void> RememberInitialReplayGuards(const std::string& session_id,
                                           const std::vector<uint8_t>& transcript_hash);
  bool HasSeenInitialReplayGuard(const std::string& session_id,
                                 const std::vector<uint8_t>& transcript_hash) const;
  static Result<std::string> ComputeSafetyNumber(
      const std::string& peer_user,
      const std::vector<uint8_t>& sign_public_key,
      const std::vector<uint8_t>& mldsa_public_key,
      const std::vector<uint8_t>& dh_public_key);

  Result<void> RefillOneTimePrekeyPools();
  Result<uint32_t> GenerateUniqueOneTimePrekeyId() const;
  Result<void> SaveLocalState() const;
  Result<void> LoadLocalState();

  static Result<std::string> NewSessionId();
  static std::string DefaultLocalStatePath(const std::string& user_id);

  std::string user_id_;
  std::string local_state_path_;

  crypto::Ed25519KeyPair identity_sign_key_;
  crypto::MlDsa65KeyPair identity_mldsa_key_;
  crypto::X25519KeyPair identity_dh_key_;

  protocol::SignedPrekeyEc signed_prekey_ec_public_;
  crypto::X25519KeyPair signed_prekey_ec_private_;

  protocol::SignedPrekeyPq signed_prekey_pq_public_;
  crypto::MlKemKeyPair signed_prekey_pq_private_;

  std::vector<OneTimeEc> one_time_ec_pool_;
  std::vector<OneTimePq> one_time_pq_pool_;
  bool prekeys_dirty_ = false;
  std::optional<uint64_t> pending_inbox_ack_up_to_id_;

  std::unordered_map<std::string, PeerIdentity> trusted_peer_identities_;
  std::unordered_map<std::string, SessionState> sessions_by_peer_;
  std::unordered_set<std::string> seen_initial_session_ids_;
  std::unordered_set<std::string> seen_initial_transcript_hashes_;
  std::deque<std::string> seen_initial_session_order_;
  std::deque<std::string> seen_initial_transcript_order_;

  static constexpr uint64_t kRatchetInterval = 10;
  static constexpr size_t kOneTimePrekeyPoolTarget = 16;
  static constexpr size_t kMaxInboxDrainPasses = 64;
  static constexpr size_t kMaxInitialReplayGuards = 4096;
  static constexpr size_t kMaxPersistedSessions = 256;
  static constexpr size_t kMaxPersistedPeers = 1024;
};

}  // namespace pqchat::client
