#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
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

  Client() = default;

  Result<void> HandleInitialMessage(const protocol::InitialMessage& message,
                                    std::vector<std::string>* plaintext_out);

  Result<void> HandleChatMessage(const protocol::ChatMessage& message,
                                 std::vector<std::string>* plaintext_out);

  static Result<std::string> NewSessionId();

  std::string user_id_;

  crypto::Ed25519KeyPair identity_sign_key_;
  crypto::MlDsa65KeyPair identity_mldsa_key_;
  crypto::X25519KeyPair identity_dh_key_;

  protocol::SignedPrekeyEc signed_prekey_ec_public_;
  crypto::X25519KeyPair signed_prekey_ec_private_;

  protocol::SignedPrekeyPq signed_prekey_pq_public_;
  crypto::MlKemKeyPair signed_prekey_pq_private_;

  std::optional<OneTimeEc> one_time_ec_;
  std::optional<OneTimePq> one_time_pq_;

  std::unordered_map<std::string, SessionState> sessions_by_peer_;

  static constexpr uint64_t kRatchetInterval = 10;
};

}  // namespace pqchat::client
