#include "pqchat/protocol/transport_auth.h"

namespace pqchat::protocol {
namespace {

void AppendU32(std::vector<uint8_t>* out, uint32_t value) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

void AppendU64(std::vector<uint8_t>* out, uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

void AppendBytes(std::vector<uint8_t>* out, const std::vector<uint8_t>& value) {
  AppendU32(out, static_cast<uint32_t>(value.size()));
  out->insert(out->end(), value.begin(), value.end());
}

void AppendString(std::vector<uint8_t>* out, const std::string& value) {
  AppendBytes(out, std::vector<uint8_t>(value.begin(), value.end()));
}

}  // namespace

std::vector<uint8_t> BuildTransportAuthSignInput(
    const std::string& user_id,
    const std::vector<uint8_t>& client_nonce,
    const std::vector<uint8_t>& server_nonce,
    const std::string& challenge_id,
    uint64_t expires_at_unix) {
  std::vector<uint8_t> out;
  AppendString(&out, "pqchat_transport_auth_v1");
  AppendString(&out, user_id);
  AppendBytes(&out, client_nonce);
  AppendBytes(&out, server_nonce);
  AppendString(&out, challenge_id);
  AppendU64(&out, expires_at_unix);
  return out;
}

std::vector<uint8_t> BuildTransportRegisterSignInput(
    const std::string& user_id,
    const std::vector<uint8_t>& new_transport_auth_public_key) {
  std::vector<uint8_t> out;
  AppendString(&out, "pqchat_transport_register_v1");
  AppendString(&out, user_id);
  AppendBytes(&out, new_transport_auth_public_key);
  return out;
}

std::vector<uint8_t> BuildTransportRegisterRotateSignInput(
    const std::string& user_id,
    const std::vector<uint8_t>& existing_transport_auth_public_key,
    const std::vector<uint8_t>& new_transport_auth_public_key) {
  std::vector<uint8_t> out;
  AppendString(&out, "pqchat_transport_register_rotate_v1");
  AppendString(&out, user_id);
  AppendBytes(&out, existing_transport_auth_public_key);
  AppendBytes(&out, new_transport_auth_public_key);
  return out;
}

}  // namespace pqchat::protocol
