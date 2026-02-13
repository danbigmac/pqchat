#include "pqchat/server/in_memory_server.h"

#include <chrono>
#include <iomanip>
#include <sstream>

#include <openssl/rand.h>

#include "pqchat/crypto/mldsa.h"
#include "pqchat/protocol/transport_auth.h"

namespace pqchat::server {

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

Result<void> InMemoryServer::RegisterTransportIdentity(
    const protocol::RegisterRequest& request) {
  std::scoped_lock lock(mu_);
  auto it = transport_identities_.find(request.user_id);
  if (it == transport_identities_.end()) {
    transport_identities_[request.user_id] = request.transport_auth_public_key;
    return Result<void>::Ok();
  }

  if (it->second != request.transport_auth_public_key) {
    return Result<void>::Err("transport identity already registered with different key");
  }
  return Result<void>::Ok();
}

Result<protocol::AuthBeginResponse> InMemoryServer::BeginTransportAuthentication(
    const protocol::AuthBeginRequest& request) {
  std::scoped_lock lock(mu_);
  auto it = transport_identities_.find(request.user_id);
  if (it == transport_identities_.end()) {
    return Result<protocol::AuthBeginResponse>::Err("unknown user");
  }

  protocol::AuthBeginResponse response;
  response.challenge_id = RandomHex(16);
  response.server_nonce = RandomBytes(32);
  response.expires_at_unix = NowUnix() + 60;
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
  if (NowUnix() > challenge.expires_at_unix) {
    return Result<protocol::AuthFinishResponse>::Err("challenge expired");
  }

  auto identity_it = transport_identities_.find(request.user_id);
  if (identity_it == transport_identities_.end()) {
    return Result<protocol::AuthFinishResponse>::Err("unknown user");
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

  challenge.used = true;

  protocol::AuthFinishResponse response;
  response.session_token = RandomBytes(32);
  response.expires_at_unix = NowUnix() + 900;
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
  std::ostringstream key;
  key << std::hex << std::setfill('0');
  for (uint8_t b : session_token) {
    key << std::setw(2) << static_cast<int>(b);
  }
  auto it = sessions_.find(key.str());
  if (it == sessions_.end()) {
    return Result<std::string>::Err("invalid session");
  }
  if (NowUnix() > it->second.expires_at_unix) {
    return Result<std::string>::Err("session expired");
  }
  return Result<std::string>::Ok(it->second.user_id);
}

Result<void> InMemoryServer::PublishBundle(const protocol::PrekeyBundle& bundle) {
  std::scoped_lock lock(mu_);

  BundleStore store;
  store.base_bundle = bundle;

  if (bundle.one_time_ec.has_value()) {
    store.one_time_ec_pool.push_back(*bundle.one_time_ec);
    store.base_bundle.one_time_ec = std::nullopt;
  }
  if (bundle.one_time_pq.has_value()) {
    store.one_time_pq_pool.push_back(*bundle.one_time_pq);
    store.base_bundle.one_time_pq = std::nullopt;
  }

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

  if (!it->second.one_time_ec_pool.empty()) {
    out.one_time_ec = it->second.one_time_ec_pool.back();
    it->second.one_time_ec_pool.pop_back();
  }

  if (!it->second.one_time_pq_pool.empty()) {
    out.one_time_pq = it->second.one_time_pq_pool.back();
    it->second.one_time_pq_pool.pop_back();
  }

  return Result<protocol::PrekeyBundle>::Ok(std::move(out));
}

Result<void> InMemoryServer::EnqueueEnvelope(const std::string& user_id,
                                             protocol::Envelope envelope) {
  std::scoped_lock lock(mu_);
  inbox_[user_id].push_back(std::move(envelope));
  return Result<void>::Ok();
}

Result<std::vector<protocol::Envelope>> InMemoryServer::DrainInbox(
    const std::string& user_id) {
  std::scoped_lock lock(mu_);

  std::vector<protocol::Envelope> out;
  auto it = inbox_.find(user_id);
  if (it == inbox_.end()) {
    return Result<std::vector<protocol::Envelope>>::Ok(std::move(out));
  }

  out.reserve(it->second.size());
  while (!it->second.empty()) {
    out.push_back(std::move(it->second.front()));
    it->second.pop_front();
  }

  return Result<std::vector<protocol::Envelope>>::Ok(std::move(out));
}

}  // namespace pqchat::server
