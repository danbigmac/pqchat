#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pqchat::protocol {

struct RegisterRequest {
  std::string user_id;
  std::vector<uint8_t> transport_auth_public_key;
};

struct AuthBeginRequest {
  std::string user_id;
  std::vector<uint8_t> client_nonce;
};

struct AuthBeginResponse {
  std::string challenge_id;
  std::vector<uint8_t> server_nonce;
  uint64_t expires_at_unix = 0;
};

struct AuthFinishRequest {
  std::string user_id;
  std::string challenge_id;
  std::vector<uint8_t> client_nonce;
  std::vector<uint8_t> server_nonce;
  uint64_t expires_at_unix = 0;
  std::vector<uint8_t> signature_mldsa65;
};

struct AuthFinishResponse {
  std::vector<uint8_t> session_token;
  uint64_t expires_at_unix = 0;
};

struct AuthenticatedPayload {
  std::vector<uint8_t> session_token;
  std::vector<uint8_t> payload;
};

std::vector<uint8_t> BuildTransportAuthSignInput(
    const std::string& user_id,
    const std::vector<uint8_t>& client_nonce,
    const std::vector<uint8_t>& server_nonce,
    const std::string& challenge_id,
    uint64_t expires_at_unix);

}  // namespace pqchat::protocol
