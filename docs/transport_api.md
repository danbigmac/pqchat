# PQChat Transport/API (TCP/TLS + SQLite)

## Overview
Server API runs over TCP with binary framed messages.
In deployment, TLS should be enabled and clients should verify server certificates.

Frame format:
- `u32 type`
- `u32 payload_len`
- `payload` bytes

## Authentication Model
- Transport auth key: `ML-DSA-65` public key registered per `user_id`
- Optional provisioning gate: first-time `RegisterTransportIdentity` may require a user-bound provisioning token (HMAC-SHA256 over `user_id` using server provisioning secret)
- Login: challenge/response signed with ML-DSA-65
- Session: short-lived opaque bearer token (stored server-side as HMAC hash)

Authenticated commands carry:
- `session_token`
- command-specific payload

Server binds actions to authenticated user identity.

## Commands
- `1` = `PublishBundle` (authenticated)
- `2` = `AcquireBundle` (authenticated)
- `3` = `EnqueueEnvelope` (authenticated)
- `4` = `DrainInbox` (authenticated)
- `5` = `RegisterTransportIdentity` (unauthenticated)
- `6` = `AuthBegin` (unauthenticated)
- `7` = `AuthFinish` (unauthenticated)

`DrainInbox` payload:
- request: `{user_id, ack_up_to_inbox_id?}`
- response: `[{inbox_id, envelope}]` ordered by `inbox_id`
- semantics: server deletes entries `<= ack_up_to_inbox_id` for `user_id`, then returns the next bounded page of remaining entries.
- clients should loop `DrainInbox` until an empty page is returned.

## Login Flow
1. `RegisterTransportIdentity`
   - payload: `{user_id, transport_auth_public_key, registration_token}`
2. `AuthBegin`
   - payload: `{user_id, client_nonce}`
   - response: `{challenge_id, server_nonce, expires_at_unix}`
3. `AuthFinish`
   - payload: `{user_id, challenge_id, client_nonce, server_nonce, expires_at_unix, signature_mldsa65}`
   - signature input:
     - `"pqchat_transport_auth_v1"`
     - `user_id`
     - `client_nonce`
     - `server_nonce`
     - `challenge_id`
     - `expires_at_unix`
   - response: `{session_token, expires_at_unix}`

## Response Status
- `0` = success
- `1` = error
  - payload is serialized error string

## Storage
SQLite schema is initialized automatically on startup:
- `accounts`
- `auth_challenges`
- `sessions`
- `bundles`
- `one_time_ec`
- `one_time_pq`
- `inbox`

`AcquireBundle` returns the publisher-signed one-time prekey lists currently stored for the user.
One-time prekey consumption happens on the receiving client when an initial message references a specific prekey ID.

## Security Enforcement
- `PublishBundle`: `bundle.user_id` must match authenticated session user.
- `EnqueueEnvelope`: envelope sender (`from_user`) must match authenticated session user.
- `DrainInbox`: requested user must match authenticated session user.
- Session token expiry and challenge expiry/reuse are enforced.

## Notes
- Payloads use canonical binary serialization (`src/protocol/serialization.cpp`).
- Server and CLI defaults are secure-by-default: TLS is required unless `--allow-insecure-dev` is set.
- TLS options:
  - server: `--tls-cert`, `--tls-key`, optional `--tls-client-ca`, `--tls-require-client-cert`
  - client: `--tls-ca`, optional `--tls-server-name`, `--tls-client-cert`, `--tls-client-key`
