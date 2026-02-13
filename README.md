# pqchat (first draft)

Two-party chat prototype with Signal-style structure and hybrid post-quantum handshake/authentication.

## Security profile (draft)
- Hybrid initial key agreement: `X25519 + ML-KEM-768`
- Hybrid authentication for signed prekeys + handshake transcript: `Ed25519 + ML-DSA-65`
- One-time prekeys (EC + PQ)
- AEAD payload encryption: `ChaCha20-Poly1305`
- HKDF-SHA256 key schedule
- Symmetric chain + periodic DH ratchet step
- Replay rejection via strict per-chain counters

Design doc: `docs/first_draft_design.md`
Transport/API spec: `docs/transport_api.md`

## What is implemented now
- Persistent server storage with SQLite (`bundles`, `one_time_prekeys`, `inbox`)
- Real TCP/TLS transport/API between clients and server (binary framed protocol)
- Transport authentication: ML-DSA challenge/response login + short-lived session tokens
- Network client adapter used by client session logic
- Interactive CLI clients for separate processes/users
- In-memory backend retained for tests and local simulation

## Binaries
- `pqchat_server`: SQLite-backed TCP server
- `pqchat_client_cli`: interactive network client (`publish`, `init`, `send`, `poll`)
- `pqchat_network_demo`: automated two-user flow over TCP
- `pqchat_tests`: integration tests (in-memory backend)

## Build
CMake build (recommended):
```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

If CMake is not installed, compile directly with `clang++/g++` and link `-lcrypto -lsqlite3`.

## Run with TLS (recommended)
1. Generate a local dev certificate:
```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/pqchat_server.key \
  -out /tmp/pqchat_server.crt \
  -days 7 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

2. Start server with TLS:
```bash
./build/pqchat_server \
  --db /tmp/pqchat.db \
  --port 19090 \
  --tls-cert /tmp/pqchat_server.crt \
  --tls-key /tmp/pqchat_server.key
```

3. Start client terminal A:
```bash
./build/pqchat_client_cli \
  --user alice \
  --host 127.0.0.1 \
  --port 19090 \
  --tls-ca /tmp/pqchat_server.crt \
  --tls-server-name localhost
```
Run:
```text
publish
init bob hello bob
```

4. Start client terminal B:
```bash
./build/pqchat_client_cli \
  --user bob \
  --host 127.0.0.1 \
  --port 19090 \
  --tls-ca /tmp/pqchat_server.crt \
  --tls-server-name localhost
```
Run:
```text
publish
poll
send alice hello alice
```

5. Back in terminal A:
```text
poll
```

## Run without TLS (dev only)
1. Start server:
```bash
./build/pqchat_server --db /tmp/pqchat.db --port 19090
```

2. Start client terminal A:
```bash
./build/pqchat_client_cli --user alice --host 127.0.0.1 --port 19090
```
Run:
```text
publish
init bob hello bob
```

3. Start client terminal B:
```bash
./build/pqchat_client_cli --user bob --host 127.0.0.1 --port 19090
```
Run:
```text
publish
poll
send alice hello alice
```

4. Back in terminal A:
```text
poll
```

## Current limitations
- Client identity/session state is in-memory only (not persisted locally yet)
- Strict in-order receive (no skipped-key cache / out-of-order window)
- Simplified ratchet (periodic DH step, not full Double Ratchet state)
- TLS server certificate lifecycle/rotation and revocation are not implemented yet
