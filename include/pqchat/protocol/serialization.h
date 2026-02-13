#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "pqchat/protocol/messages.h"
#include "pqchat/protocol/prekey_bundle.h"
#include "pqchat/protocol/transport_auth.h"
#include "pqchat/util/result.h"

namespace pqchat::protocol {

struct EnqueueRequest {
  std::string user_id;
  Envelope envelope;
};

Result<std::vector<uint8_t>> SerializePrekeyBundle(const PrekeyBundle& bundle);
Result<PrekeyBundle> DeserializePrekeyBundle(const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeEnvelope(const Envelope& envelope);
Result<Envelope> DeserializeEnvelope(const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeEnvelopeVector(
    const std::vector<Envelope>& envelopes);
Result<std::vector<Envelope>> DeserializeEnvelopeVector(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeString(const std::string& value);
Result<std::string> DeserializeString(const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeEnqueueRequest(
    const EnqueueRequest& request);
Result<EnqueueRequest> DeserializeEnqueueRequest(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeRegisterRequest(
    const RegisterRequest& request);
Result<RegisterRequest> DeserializeRegisterRequest(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeAuthBeginRequest(
    const AuthBeginRequest& request);
Result<AuthBeginRequest> DeserializeAuthBeginRequest(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeAuthBeginResponse(
    const AuthBeginResponse& response);
Result<AuthBeginResponse> DeserializeAuthBeginResponse(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeAuthFinishRequest(
    const AuthFinishRequest& request);
Result<AuthFinishRequest> DeserializeAuthFinishRequest(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeAuthFinishResponse(
    const AuthFinishResponse& response);
Result<AuthFinishResponse> DeserializeAuthFinishResponse(
    const std::vector<uint8_t>& bytes);

Result<std::vector<uint8_t>> SerializeAuthenticatedPayload(
    const AuthenticatedPayload& payload);
Result<AuthenticatedPayload> DeserializeAuthenticatedPayload(
    const std::vector<uint8_t>& bytes);

}  // namespace pqchat::protocol
