#include "pqchat/server/in_memory_server.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/protocol/serialization.h"
#include "pqchat/protocol/transport_auth.h"

namespace pqchat::server {
namespace {

constexpr size_t kMaxUserIdBytes = 64;
constexpr size_t kMaxTransportAuthPublicKeyBytes = 8192;
constexpr size_t kExpectedAuthNonceBytes = 32;
constexpr size_t kExpectedSessionTokenBytes = 32;
constexpr size_t kMinMlDsaSignatureBytes = 64;
constexpr size_t kMaxMlDsaSignatureBytes = 8192;
constexpr size_t kChallengeIdHexBytes = 32;
constexpr size_t kMaxDrainInboxBatchItems = 128;
constexpr size_t kMaxDrainInboxBatchBytes = 512 * 1024;
constexpr uint64_t kAuthRateWindowSeconds = 60;
constexpr size_t kMaxAuthBeginAttemptsPerWindow = 30;
constexpr size_t kMaxAuthFinishAttemptsPerWindow = 30;

bool IsValidUserId(const std::string& user_id) {
  if (user_id.empty() || user_id.size() > kMaxUserIdBytes) {
    return false;
  }

  for (unsigned char c : user_id) {
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
        c == '.') {
      continue;
    }
    return false;
  }

  return true;
}

int HexValue(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

bool IsValidHexString(const std::string& value) {
  for (char c : value) {
    if (HexValue(c) < 0) {
      return false;
    }
  }
  return true;
}

bool IsValidChallengeId(const std::string& challenge_id) {
  return challenge_id.size() == kChallengeIdHexBytes &&
         IsValidHexString(challenge_id);
}

Result<std::vector<uint8_t>> DecodeHex(const std::string& hex) {
  if ((hex.size() % 2) != 0) {
    return Result<std::vector<uint8_t>>::Err("invalid hex length");
  }

  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = HexValue(hex[i]);
    int lo = HexValue(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return Result<std::vector<uint8_t>>::Err("invalid hex character");
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<void> VerifyProvisioningToken(const std::string& provisioning_secret,
                                     const std::string& user_id,
                                     const std::string& token_hex) {
  auto expected = crypto::HmacSha256(crypto::ToBytes(provisioning_secret),
                                     crypto::ToBytes(user_id));
  if (!expected.ok()) {
    return Result<void>::Err("failed to derive registration token");
  }

  const auto& expected_bytes = expected.value();
  if (token_hex.size() != expected_bytes.size() * 2) {
    return Result<void>::Err("invalid registration token");
  }

  auto provided = DecodeHex(token_hex);
  if (!provided.ok()) {
    return Result<void>::Err("invalid registration token");
  }

  const auto& provided_bytes = provided.value();
  if (expected_bytes.size() != provided_bytes.size()) {
    return Result<void>::Err("invalid registration token");
  }
  if (CRYPTO_memcmp(expected_bytes.data(),
                    provided_bytes.data(),
                    expected_bytes.size()) != 0) {
    return Result<void>::Err("invalid registration token");
  }
  return Result<void>::Ok();
}

}  // namespace

InMemoryServer::InMemoryServer(std::string required_registration_token)
    : required_registration_token_(std::move(required_registration_token)) {}

uint64_t InMemoryServer::NowUnix() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::vector<uint8_t> InMemoryServer::RandomBytes(size_t bytes) {
  std::vector<uint8_t> out(bytes);
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    return {};
  }
  return out;
}

std::string InMemoryServer::RandomHex(size_t bytes) {
  auto data = RandomBytes(bytes);
  if (data.empty()) {
    return {};
  }
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : data) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

void InMemoryServer::CleanupAuthState(uint64_t now) {
  for (auto it = challenges_.begin(); it != challenges_.end();) {
    if (it->second.used || it->second.expires_at_unix < now) {
      it = challenges_.erase(it);
      continue;
    }
    ++it;
  }

  for (auto it = sessions_.begin(); it != sessions_.end();) {
    if (it->second.expires_at_unix < now) {
      it = sessions_.erase(it);
      continue;
    }
    ++it;
  }

  auto trim_buckets = [now](std::unordered_map<std::string, std::deque<uint64_t>>* buckets) {
    for (auto it = buckets->begin(); it != buckets->end();) {
      auto& window = it->second;
      while (!window.empty() && window.front() + kAuthRateWindowSeconds <= now) {
        window.pop_front();
      }
      if (window.empty()) {
        it = buckets->erase(it);
        continue;
      }
      ++it;
    }
  };
  trim_buckets(&auth_begin_attempts_);
  trim_buckets(&auth_finish_attempts_);
}

Result<void> InMemoryServer::EnforceRateLimit(
    std::unordered_map<std::string, std::deque<uint64_t>>* buckets,
    const std::string& user_id,
    uint64_t now,
    size_t max_attempts,
    uint64_t window_seconds,
    const char* error_text) {
  auto& bucket = (*buckets)[user_id];
  while (!bucket.empty() && bucket.front() + window_seconds <= now) {
    bucket.pop_front();
  }
  if (bucket.size() >= max_attempts) {
    return Result<void>::Err(error_text);
  }
  bucket.push_back(now);
  return Result<void>::Ok();
}

Result<void> InMemoryServer::RegisterTransportIdentity(
    const protocol::RegisterRequest& request) {
  std::scoped_lock lock(mu_);
  if (!IsValidUserId(request.user_id)) {
    return Result<void>::Err(
        "invalid user_id (allowed: lowercase a-z, 0-9, '-', '_', '.', max 64)");
  }
  if (request.transport_auth_public_key.empty() ||
      request.transport_auth_public_key.size() > kMaxTransportAuthPublicKeyBytes) {
    return Result<void>::Err("invalid transport auth public key size");
  }
  if (request.proof_signature_mldsa65.size() < kMinMlDsaSignatureBytes ||
      request.proof_signature_mldsa65.size() > kMaxMlDsaSignatureBytes) {
    return Result<void>::Err("invalid registration proof signature size");
  }
  if (request.rotation_signature_mldsa65.has_value() &&
      (request.rotation_signature_mldsa65->size() < kMinMlDsaSignatureBytes ||
       request.rotation_signature_mldsa65->size() > kMaxMlDsaSignatureBytes)) {
    return Result<void>::Err("invalid rotation signature size");
  }

  auto register_sign_input = protocol::BuildTransportRegisterSignInput(
      request.user_id, request.transport_auth_public_key);
  auto register_sig_ok = crypto::MlDsa65::Verify(request.transport_auth_public_key,
                                                 register_sign_input,
                                                 request.proof_signature_mldsa65);
  if (!register_sig_ok.ok()) {
    return Result<void>::Err("transport identity registration proof invalid");
  }

  auto it = transport_identities_.find(request.user_id);
  if (it == transport_identities_.end()) {
    if (!required_registration_token_.empty()) {
      auto token_verify = VerifyProvisioningToken(required_registration_token_,
                                                  request.user_id,
                                                  request.registration_token);
      if (!token_verify.ok()) {
        return token_verify;
      }
    }
    transport_identities_[request.user_id] = request.transport_auth_public_key;
    return Result<void>::Ok();
  }

  if (it->second != request.transport_auth_public_key) {
    bool rotated = false;
    if (request.rotation_signature_mldsa65.has_value()) {
      auto rotate_sign_input = protocol::BuildTransportRegisterRotateSignInput(
          request.user_id,
          it->second,
          request.transport_auth_public_key);
      auto rotate_sig_ok = crypto::MlDsa65::Verify(it->second,
                                                   rotate_sign_input,
                                                   *request.rotation_signature_mldsa65);
      rotated = rotate_sig_ok.ok();
    }

    bool recovered = false;
    if (!rotated && !required_registration_token_.empty()) {
      auto token_verify = VerifyProvisioningToken(required_registration_token_,
                                                  request.user_id,
                                                  request.registration_token);
      recovered = token_verify.ok();
    }

    if (!rotated && !recovered) {
      return Result<void>::Err(
          "transport identity already registered with different key (rotation/recovery required)");
    }
    it->second = request.transport_auth_public_key;
    for (auto session_it = sessions_.begin(); session_it != sessions_.end();) {
      if (session_it->second.user_id == request.user_id) {
        session_it = sessions_.erase(session_it);
        continue;
      }
      ++session_it;
    }
    return Result<void>::Ok();
  }
  return Result<void>::Ok();
}

Result<protocol::AuthBeginResponse> InMemoryServer::BeginTransportAuthentication(
    const protocol::AuthBeginRequest& request) {
  std::scoped_lock lock(mu_);
  const uint64_t now = NowUnix();
  CleanupAuthState(now);
  if (!IsValidUserId(request.user_id)) {
    return Result<protocol::AuthBeginResponse>::Err("invalid user_id");
  }
  if (request.client_nonce.size() != kExpectedAuthNonceBytes) {
    return Result<protocol::AuthBeginResponse>::Err("invalid client nonce size");
  }

  auto limit = EnforceRateLimit(&auth_begin_attempts_,
                                request.user_id,
                                now,
                                kMaxAuthBeginAttemptsPerWindow,
                                kAuthRateWindowSeconds,
                                "auth begin rate limit exceeded");
  if (!limit.ok()) {
    return Result<protocol::AuthBeginResponse>::Err(limit.error());
  }

  auto it = transport_identities_.find(request.user_id);
  if (it == transport_identities_.end()) {
    return Result<protocol::AuthBeginResponse>::Err("authentication failed");
  }

  protocol::AuthBeginResponse response;
  response.challenge_id = RandomHex(16);
  response.server_nonce = RandomBytes(32);
  response.expires_at_unix = now + 60;
  if (response.challenge_id.empty() || response.server_nonce.empty()) {
    return Result<protocol::AuthBeginResponse>::Err("RNG failed");
  }

  ChallengeState state;
  state.user_id = request.user_id;
  state.client_nonce = request.client_nonce;
  state.server_nonce = response.server_nonce;
  state.expires_at_unix = response.expires_at_unix;
  challenges_[response.challenge_id] = std::move(state);

  return Result<protocol::AuthBeginResponse>::Ok(std::move(response));
}

Result<protocol::AuthFinishResponse> InMemoryServer::FinishTransportAuthentication(
    const protocol::AuthFinishRequest& request) {
  std::scoped_lock lock(mu_);
  const uint64_t now = NowUnix();
  CleanupAuthState(now);
  if (!IsValidUserId(request.user_id)) {
    return Result<protocol::AuthFinishResponse>::Err("invalid user_id");
  }
  if (!IsValidChallengeId(request.challenge_id)) {
    return Result<protocol::AuthFinishResponse>::Err("invalid challenge id");
  }
  if (request.client_nonce.size() != kExpectedAuthNonceBytes ||
      request.server_nonce.size() != kExpectedAuthNonceBytes) {
    return Result<protocol::AuthFinishResponse>::Err("invalid auth nonce size");
  }
  if (request.signature_mldsa65.size() < kMinMlDsaSignatureBytes ||
      request.signature_mldsa65.size() > kMaxMlDsaSignatureBytes) {
    return Result<protocol::AuthFinishResponse>::Err("invalid auth signature size");
  }

  auto limit = EnforceRateLimit(&auth_finish_attempts_,
                                request.user_id,
                                now,
                                kMaxAuthFinishAttemptsPerWindow,
                                kAuthRateWindowSeconds,
                                "auth finish rate limit exceeded");
  if (!limit.ok()) {
    return Result<protocol::AuthFinishResponse>::Err(limit.error());
  }

  auto challenge_it = challenges_.find(request.challenge_id);
  if (challenge_it == challenges_.end()) {
    return Result<protocol::AuthFinishResponse>::Err("unknown challenge");
  }
  auto& challenge = challenge_it->second;

  if (challenge.used) {
    return Result<protocol::AuthFinishResponse>::Err("challenge already used");
  }
  if (challenge.user_id != request.user_id ||
      challenge.client_nonce != request.client_nonce ||
      challenge.server_nonce != request.server_nonce ||
      challenge.expires_at_unix != request.expires_at_unix) {
    return Result<protocol::AuthFinishResponse>::Err("challenge mismatch");
  }
  if (now > challenge.expires_at_unix) {
    return Result<protocol::AuthFinishResponse>::Err("challenge expired");
  }
  challenge.used = true;

  auto identity_it = transport_identities_.find(request.user_id);
  if (identity_it == transport_identities_.end()) {
    return Result<protocol::AuthFinishResponse>::Err("authentication failed");
  }

  auto sign_input = protocol::BuildTransportAuthSignInput(
      request.user_id,
      request.client_nonce,
      request.server_nonce,
      request.challenge_id,
      request.expires_at_unix);
  auto verify = crypto::MlDsa65::Verify(identity_it->second,
                                        sign_input,
                                        request.signature_mldsa65);
  if (!verify.ok()) {
    return Result<protocol::AuthFinishResponse>::Err("auth signature invalid");
  }

  protocol::AuthFinishResponse response;
  response.session_token = RandomBytes(32);
  response.expires_at_unix = now + 900;
  if (response.session_token.empty()) {
    return Result<protocol::AuthFinishResponse>::Err("RNG failed");
  }

  std::ostringstream key;
  key << std::hex << std::setfill('0');
  for (uint8_t b : response.session_token) {
    key << std::setw(2) << static_cast<int>(b);
  }
  sessions_[key.str()] = SessionState{request.user_id, response.expires_at_unix};

  return Result<protocol::AuthFinishResponse>::Ok(std::move(response));
}

Result<std::string> InMemoryServer::AuthenticateSessionToken(
    const std::vector<uint8_t>& session_token) {
  std::scoped_lock lock(mu_);
  const uint64_t now = NowUnix();
  CleanupAuthState(now);
  if (session_token.size() != kExpectedSessionTokenBytes) {
    return Result<std::string>::Err("invalid session token size");
  }
  std::ostringstream key;
  key << std::hex << std::setfill('0');
  for (uint8_t b : session_token) {
    key << std::setw(2) << static_cast<int>(b);
  }
  auto it = sessions_.find(key.str());
  if (it == sessions_.end()) {
    return Result<std::string>::Err("invalid session");
  }
  if (now > it->second.expires_at_unix) {
    return Result<std::string>::Err("session expired");
  }
  return Result<std::string>::Ok(it->second.user_id);
}

Result<void> InMemoryServer::RevokeSessionToken(
    const std::vector<uint8_t>& session_token) {
  std::scoped_lock lock(mu_);
  if (session_token.size() != kExpectedSessionTokenBytes) {
    return Result<void>::Err("invalid session token size");
  }
  std::ostringstream key;
  key << std::hex << std::setfill('0');
  for (uint8_t b : session_token) {
    key << std::setw(2) << static_cast<int>(b);
  }
  auto it = sessions_.find(key.str());
  if (it == sessions_.end()) {
    return Result<void>::Err("invalid session");
  }
  sessions_.erase(it);
  return Result<void>::Ok();
}

Result<void> InMemoryServer::PublishBundle(const protocol::PrekeyBundle& bundle) {
  std::scoped_lock lock(mu_);
  if (bundle.version != protocol::kProtocolVersion) {
    return Result<void>::Err("unsupported bundle version");
  }
  if (bundle.cipher_suite != protocol::kCipherSuite) {
    return Result<void>::Err("unsupported bundle cipher suite");
  }
  auto verify = protocol::VerifyPrekeyBundleSignatures(bundle);
  if (!verify.ok()) {
    return Result<void>::Err("invalid prekey bundle signatures: " + verify.error());
  }

  BundleStore store;
  store.base_bundle = bundle;
  store.one_time_ec_pool = bundle.one_time_ec;
  store.one_time_pq_pool = bundle.one_time_pq;

  bundles_[bundle.user_id] = std::move(store);
  return Result<void>::Ok();
}

Result<protocol::PrekeyBundle> InMemoryServer::AcquireBundleForSession(
    const std::string& user_id) {
  std::scoped_lock lock(mu_);

  auto it = bundles_.find(user_id);
  if (it == bundles_.end()) {
    return Result<protocol::PrekeyBundle>::Err("no prekey bundle for user");
  }

  protocol::PrekeyBundle out = it->second.base_bundle;
  out.one_time_ec.clear();
  out.one_time_pq.clear();
  if (!it->second.one_time_ec_pool.empty() && !it->second.one_time_pq_pool.empty()) {
    out.one_time_ec.push_back(it->second.one_time_ec_pool.front());
    out.one_time_pq.push_back(it->second.one_time_pq_pool.front());
    it->second.one_time_ec_pool.erase(it->second.one_time_ec_pool.begin());
    it->second.one_time_pq_pool.erase(it->second.one_time_pq_pool.begin());
  }

  return Result<protocol::PrekeyBundle>::Ok(std::move(out));
}

Result<void> InMemoryServer::EnqueueEnvelope(const std::string& user_id,
                                             protocol::Envelope envelope) {
  std::scoped_lock lock(mu_);
  uint64_t next_id = ++next_inbox_id_by_user_[user_id];
  inbox_[user_id].push_back(InboxEntry{next_id, std::move(envelope)});
  return Result<void>::Ok();
}

Result<std::vector<protocol::InboxEnvelope>> InMemoryServer::DrainInbox(
    const std::string& user_id,
    std::optional<uint64_t> ack_up_to_inbox_id) {
  std::scoped_lock lock(mu_);

  std::vector<protocol::InboxEnvelope> out;
  auto it = inbox_.find(user_id);
  if (it == inbox_.end()) {
    return Result<std::vector<protocol::InboxEnvelope>>::Ok(std::move(out));
  }

  if (ack_up_to_inbox_id.has_value()) {
    while (!it->second.empty() && it->second.front().inbox_id <= *ack_up_to_inbox_id) {
      it->second.pop_front();
    }
  }

  out.reserve(std::min(it->second.size(), kMaxDrainInboxBatchItems));
  size_t total_payload_bytes = 0;
  for (const auto& entry : it->second) {
    auto encoded = protocol::SerializeEnvelope(entry.envelope);
    if (!encoded.ok()) {
      return Result<std::vector<protocol::InboxEnvelope>>::Err(encoded.error());
    }
    size_t estimated_size = encoded.value().size() + sizeof(uint64_t) + 8;
    if (!out.empty() &&
        (out.size() >= kMaxDrainInboxBatchItems ||
         total_payload_bytes + estimated_size > kMaxDrainInboxBatchBytes)) {
      break;
    }
    total_payload_bytes += estimated_size;
    out.push_back(protocol::InboxEnvelope{entry.inbox_id, entry.envelope});
  }

  return Result<std::vector<protocol::InboxEnvelope>>::Ok(std::move(out));
}

}  // namespace pqchat::server
