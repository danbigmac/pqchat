# PQChat First Draft Design (OpenSSL, Industry-Standard Profile)

## 1. Goals and Non-Goals

### Goals
- Build a two-party chat system with a strong baseline security model.
- Use OpenSSL primitives, including post-quantum ML-KEM and ML-DSA where available.
- Follow Signal-style protocol structure:
  - Asynchronous prekey bundles
  - Authenticated hybrid key agreement (classical + PQ)
  - One-time prekeys
  - Symmetric-key ratchet + periodic DH ratchet steps
- Keep implementation modular and testable in modern C++.

### Non-Goals (First Draft)
- Group chat
- Multi-device identity management
- Contact discovery
- Full metadata protection (IP/timing/network-layer anonymity)
- Production-grade server hardening/deployment automation

## 2. Threat Model

### Defended in v1
- Passive eavesdroppers
- Active network attackers (tampering, message injection)
- Replay of transport payloads
- Future decryption from retrospective quantum adversary (hybrid KEX with ML-KEM)

### Partially Defended in v1
- Server compromise of stored ciphertexts and prekey metadata
- Client compromise with post-compromise recovery (limited by simplified ratchet cadence)

### Not Defended in v1
- Traffic analysis / strong metadata resistance
- Global active adversary fully controlling both endpoints long-term

## 3. Cryptographic Suite

### Identity and Signatures
- `Ed25519` for identity signatures (OpenSSL `EVP_PKEY_ED25519`)
- `ML-DSA-65` for post-quantum identity signatures (OpenSSL `EVP_PKEY-ML-DSA-65`)
- First draft uses hybrid authentication: prekeys and handshake transcript are signed and verified by both Ed25519 and ML-DSA-65.

### Key Agreement
- Classical: `X25519` (`EVP_PKEY_X25519`)
- Post-Quantum: `ML-KEM-768` (`EVP_PKEY-ML-KEM-768`)
- Session secret = HKDF extract over concatenated classical and PQ shared secrets.

### Symmetric Encryption
- `ChaCha20-Poly1305` (`EVP_chacha20_poly1305`)
- 96-bit nonces derived from sender message counter.

### KDF / MAC
- `HKDF-SHA256` for root/chain/message key derivation.
- `HMAC-SHA256` helper for chain progression and labels where needed.

### RNG
- `RAND_bytes` (OpenSSL DRBG)

## 4. Protocol Overview

### 4.1 Registration / Prekey Upload
Each user has:
- Identity signing keypairs (`Ed25519` and `ML-DSA-65`)
- Signed prekey `SPK` (X25519 static prekey)
- Signed PQ prekey `SPK_PQ` (ML-KEM-768 keypair)
- One-time prekeys:
  - `OPK_EC[i]` (X25519)
  - `OPK_PQ[j]` (ML-KEM-768)

Server stores prekey bundle:
- `identity_sign_pk`
- `identity_mldsa_pk`
- `spk_ec_pub`, `sig_ed25519(...)` and `sig_mldsa65(...)` over `context || spk_ec_pub || spk_ec_id`
- `spk_pq_pub`, `sig_ed25519(...)` and `sig_mldsa65(...)` over `context || spk_pq_pub || spk_pq_id`
- vectors of one-time EC/PQ public prekeys with IDs

### 4.2 Initial Handshake (Initiator Alice to Bob)
Alice fetches Bob bundle and verifies both signatures against Bob identity key.

Alice generates ephemeral X25519 key `EKa` and performs:
- `dh1 = X25519(IKa, SPKb)`
- `dh2 = X25519(EKa, IKb)`
- `dh3 = X25519(EKa, SPKb)`
- Optional if present: `dh4 = X25519(EKa, OPKb_EC)`

Alice encapsulates to Bob’s PQ keys:
- `ct_spk_pq, ss_spk_pq = Encaps(SPKb_PQ)`
- Optional: `ct_opk_pq, ss_opk_pq = Encaps(OPKb_PQ)`

`IKM = dh1 || dh2 || dh3 || [dh4] || ss_spk_pq || [ss_opk_pq]`

Transcript/AD includes:
- protocol version
- both user IDs
- both identity pubkeys
- all selected prekey IDs
- initiator ephemeral pub
- PQ ciphertext hashes

`root_key = HKDF-Extract(salt=0, IKM)`
`session_seed = HKDF-Expand(root_key, transcript_hash || "pqchat_session_v1", 96)`
Split into:
- `root_key_0`
- initiator `send_chain_key_0`
- initiator `recv_chain_key_0` (mirrored on Bob)

Alice sends `InitialMessage` containing:
- identity reference
- `EKa_pub`
- selected prekey IDs
- PQ ciphertext(s)
- optional encrypted first payload + AD binding

Bob decapsulates, recomputes same IKM, derives same keys, consumes one-time prekeys once.

### 4.3 Messaging and Ratchet

#### Symmetric Chain Step
For each sent message:
- `mk = HKDF(chain_key, "msg_key" || counter)`
- `next_chain_key = HKDF(chain_key, "chain_step" || counter)`
- nonce = 96-bit encode(counter)
- ciphertext = AEAD_Encrypt(mk, nonce, plaintext, header_ad)

Receiver tracks per-sender counters and rejects duplicates/replays.

#### Periodic DH Ratchet Step (Simplified v1)
Every `N` outbound messages (configurable, default 10), sender:
- generates fresh X25519 ratchet keypair
- publishes new ratchet pub in message header
- derives new root/chain keys from DH(ratchet_priv, peer_ratchet_pub)

This gives first-draft post-compromise recovery better than a pure symmetric chain.

## 5. Server Design (Mailbox + Prekey Service)

### Responsibilities
- Store/fetch prekey bundles
- Serve publisher-signed one-time prekey lists; responder clients consume referenced IDs locally and republish refreshed bundles
- Store encrypted envelopes by recipient
- Return envelopes in order with monotonic server sequence IDs
- Authenticate transport API callers and bind API actions to authenticated user identity

### Trust Model
- Server is untrusted for confidentiality/integrity of message body.
- Server can still observe metadata (sender/recipient/time/size).

### Storage Model (First Draft)
- SQLite-backed persistent store for server runtime (`bundles`, `one_time_ec`, `one_time_pq`, `inbox`).
- In-memory backend retained for tests/dev and deterministic integration checks.
- Transport auth tables: `accounts`, `auth_challenges`, `sessions`.

### Transport Authentication (Implemented)
- User registers transport auth public key (`ML-DSA-65`) with `RegisterTransportIdentity`.
- Login uses challenge/response:
  - `AuthBegin`: server returns challenge id + server nonce + expiry.
  - `AuthFinish`: client signs canonical auth transcript with ML-DSA-65 and receives short-lived session token.
- Authenticated commands carry session token and command payload.
- Server enforces:
  - `publish.user_id == authenticated_user`
  - `envelope.from_user == authenticated_user`
  - `drain.user_id == authenticated_user`

### Transport Encryption (Implemented)
- TCP transport supports TLS.
- Server loads X.509 certificate/private key and can optionally require client certificates.
- Client verifies server certificate chain and hostname (or explicit `server_name` override).

## 6. C++ Architecture

## Project layout
- `include/pqchat/crypto/*`: OpenSSL wrappers (RAII, no raw ownership)
- `include/pqchat/protocol/*`: wire structs + encode/decode + transcript logic
- `include/pqchat/client/*`: identity/session lifecycle
- `include/pqchat/server/*`: prekey/mailbox service interfaces
- `src/*`: implementations
- `tests/*`: unit and integration tests

### Core safety/quality rules
- `std::vector<uint8_t>` for byte buffers
- explicit `Result<T>` return type with error strings
- OpenSSL object ownership wrapped in `std::unique_ptr` with custom deleters
- secret buffers zeroized on destruction via `OPENSSL_cleanse`
- canonical serialization for all signed/transcript-bound fields

## 7. Wire Structures (Binary Framing for First Draft)

Transport command frame:
- `u32 command_or_status`
- `u32 payload_len`
- `payload` (binary canonical serialization)

Server commands:
- `PublishBundle`
- `AcquireBundle`
- `EnqueueEnvelope`
- `DrainInbox`

### PrekeyBundle
- `user_id`
- `identity_sign_public_key`
- `identity_mldsa_public_key`
- `identity_dh_public_key`
- `signed_prekey_ec`: `{id, public_key, signature_ed25519, signature_mldsa65}`
- `signed_prekey_pq`: `{id, public_key, signature_ed25519, signature_mldsa65}`
- `one_time_ec`: `{id, public_key}` (optional)
- `one_time_pq`: `{id, public_key}` (optional)
- `version`
- `cipher_suite`

### InitialMessage
- `session_id`
- `from_user`
- `to_user`
- `initiator_identity_sign_public_key`
- `initiator_identity_mldsa_public_key`
- `initiator_identity_dh_public_key`
- `initiator_ephemeral_ec_public_key`
- `selected_prekey_ids`
- `kem_ciphertext_signed_pq`
- `kem_ciphertext_one_time_pq` (optional)
- `transcript_hash`
- `handshake_signature_ed25519`
- `handshake_signature_mldsa65`
- `initial_nonce`
- `initial_ciphertext`

### ChatMessage
- `session_id`
- `header`: `{sender_ratchet_pub?, pn, n, flags}`
- `nonce`
- `ciphertext`

## 8. Error Handling and State Machine

### Session states
- `New`
- `HandshakeSent`
- `Active`
- `Closed`

Invalid transitions fail explicitly.

### Critical failures
- signature verification failure
- transcript mismatch
- missing/consumed one-time prekey referenced by initial message
- AEAD open failure
- replayed counter

## 9. Testing Strategy

### Unit tests
- Ed25519 sign/verify
- ML-DSA-65 sign/verify
- X25519 shared secret agreement
- ML-KEM encaps/decaps consistency
- HKDF deterministic vector tests
- AEAD tamper detection

### Integration tests
- full initiator/responder handshake with one-time prekeys
- both sides derive identical root/send/recv keys
- message exchange decrypts on both ends
- replayed envelope rejected
- tampered header AD rejected
- periodic ratchet step still interoperates

## 10. Hardening Roadmap (v2+)

- Replace simplified periodic DH cadence with full Double Ratchet state (skipped message key storage and out-of-order handling windows)
- Hybrid signatures (Ed25519 + ML-DSA) policy with migration/rotation
- Signed key transparency / audit log for identity keys
- MLS-style group protocol evaluation for group chat
- transport hardening (token revocation endpoint, cert rotation/revocation, rate limits)
