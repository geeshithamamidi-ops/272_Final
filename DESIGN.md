# DESIGN.md — Secure 4 GB File Transfer

---

## Approach A: Mutually-Authenticated TLS Streaming

### Architecture

```
SENDER                                       RECEIVER
------                                       --------
sender.crt + sender.key                      receiver.crt + receiver.key
       |                                            |
       |  TCP connect → TLS 1.3 ClientHello         |
       |─────────────────────────────────────────>  |
       |  TLS ServerHello + receiver.crt            |
       |<─────────────────────────────────────────  |
       |  sender.crt (client cert, mTLS)            |
       |─────────────────────────────────────────>  |
       |  TLS handshake complete (ECDHE)            |
       |━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━>  |
       |  [session_key] (32 bytes, inside TLS)      |
       |─────────────────────────────────────────>  |
       |  [session_id]  (16 bytes, inside TLS)      |
       |─────────────────────────────────────────>  |
       |                                            |
       |  For each 1 MB chunk:                      |
       |  TYPE_CHUNK | session_id | idx | AES-GCM   |
       |─────────────────────────────────────────>  |
       |  ...                                       |
       |  TYPE_MANIFEST | body | HMAC-SHA256        |
       |─────────────────────────────────────────>  |
       |                      ACK / ERR             |
       |<─────────────────────────────────────────  |
```

### Key Exchange and Key Management

- **Transport keys**: TLS 1.3 uses ECDHE (X25519 by default in Python's OpenSSL build) for the handshake.

TLS 1.3 uses ECDHE (X25519) for key exchange, which provides forward secrecy. A fresh ephemeral key pair is generated for every connection and discarded immediately after the handshake. Forward secrecy matters here because the file being transferred may remain sensitive long after the transfer completes. An attacker who records the entire TCP session today and later steals the sender's certificate private key gets nothing — the session traffic key cannot be reconstructed. Approach B has no forward secrecy: a stolen PSK allows decryption of all past recorded sessions, which is the key long-term trade-off between the two designs.

- **Session key**: A 256-bit random key is generated fresh each connection by the sender and transmitted to the receiver inside the fully-encrypted TLS channel. Both sender cert and receiver cert have been verified before this key is sent, so the key cannot be intercepted by a MITM.
- **Chunk AEAD key**: The session key is used directly for AES-256-GCM chunk encryption (no further derivation needed since it is already a fresh 256-bit random).

### Chunking and Framing

- **Chunk size**: 1 MB (1,048,576 bytes). This fits comfortably in memory, avoids excessive fragmentation, and gives the GCM counter room to breathe.
- **Frame structure**:
  ```
  [4 bytes: big-endian frame length]
  [1 byte:  message type]
  [16 bytes: session_id]
  [8 bytes:  chunk_index (big-endian)]
  [12 bytes: AES-GCM nonce]
  [N bytes:  ciphertext]
  [16 bytes: GCM authentication tag]
  ```
- **Nonce construction**: 12 bytes. Bytes 0–3 = first 4 bytes of session_id XOR'd with chunk_index (little-endian). Bytes 4–7 = bytes 4–7 of session_id. Bytes 8–11 = chunk_index (big-endian). This guarantees uniqueness within a session (chunk_index is monotonically increasing) and cross-session safety (session_id differs each run).
- **AAD (Additional Authenticated Data)**: `session_id || chunk_index (8 bytes big-endian)`. This binds each ciphertext to its exact position. A reordering attack will cause the GCM tag to fail on the reordered chunk.

### Exact Algorithms and Parameters

| Parameter | Value |
|---|---|
| TLS version | TLS 1.3 (minimum) |
| TLS key exchange | ECDHE (X25519 via system OpenSSL) |
| TLS cipher suite | TLS_AES_256_GCM_SHA384 (negotiated) |
| Chunk AEAD | AES-256-GCM |
| Key length | 256 bits (32 bytes) |
| GCM nonce | 96 bits (12 bytes), deterministic per session+index |
| GCM tag | 128 bits (16 bytes, full) |
| Manifest MAC | HMAC-SHA256 |
| End-to-end hash | SHA-256 of full plaintext |
| Cert key length | RSA-4096 |
| Cert signature | SHA-256 with RSA |

### Threat Model — Approach A

| Threat | CIAA | Mechanism |
|---|---|---|
| **Passive eavesdropper records TCP stream** | C | TLS 1.3 encrypts all data. Even the session_key transmission is inside TLS, so key material is never in plaintext on the wire. Chunk payloads are additionally AES-256-GCM encrypted at the application layer. |
| **Active MITM modifies bytes mid-flight** | I | TLS record-layer MAC + per-chunk AES-GCM tag. The AAD (session_id ∥ chunk_index) ensures any byte flip or reordering causes tag failure. The SHA-256 manifest at EOF provides a second independent integrity check over the full plaintext. |
| **Attacker spoofs sender or receiver** | A | mTLS: both sides present X.509 certificates issued by a shared CA. The receiver's `ssl.CERT_REQUIRED` rejects any connection without a valid cert. The sender verifies the receiver's CN. A wrong cert produces a hard TLS handshake failure — the session_key is never transmitted. |
| **Replay of an earlier valid transfer** | I/A | The session_key and session_id are both freshly generated per connection. Replaying a previous TLS session requires the ephemeral ECDHE private key, which is discarded after the handshake (forward secrecy). Replaying application-layer chunks from session X into session Y fails because the session_id in the chunk AAD will not match. |
| **Connection drops at 80% transferred** | A | The receiver writes to a `.partial` temp file and only promotes it to the final output path after the manifest HMAC and SHA-256 verify. On drop, the temp file is left or deleted; the final path is never written, so no partial file is silently accepted. |
| **Untrusted intermediary** | N/A | Approach A is direct sender→receiver; no broker tier. |

---

## Approach B: Pre-Shared-Key Encrypted Envelope over Plain TCP

### Architecture

```
SENDER                                         RECEIVER
------                                         --------
psk.hex  ──(out-of-band distribution)──>  psk.hex

TCP connect (plain, no TLS)

MSG_HELLO: salt(32) | sender_nonce(32)
─────────────────────────────────────────────────────>

[Receiver derives enc_key, auth_key via HKDF(PSK, salt)]

MSG_HELLO_ACK: receiver_nonce(32) | HMAC(auth_key, sn||rn)(32) | [resume_offset(8)]
<─────────────────────────────────────────────────────

[Sender verifies HMAC — proves receiver holds PSK]

For each 1 MB chunk:
MSG_CHUNK: chunk_index(8) | nonce(12) | ciphertext | tag(16)
─────────────────────────────────────────────────────>

MSG_MANIFEST: salt|chunk_count|file_size|sha256 | HMAC(auth_key, body)
─────────────────────────────────────────────────────>

MSG_ACK
<─────────────────────────────────────────────────────
```

### Key Exchange and Key Management

- **PSK distribution**: 256-bit random key generated once by `scripts/gen_psk.py`, written to a file with `chmod 600`. Distributed out-of-band (SCP, USB, courier). This is the only secret that must be shared ahead of time.
- **Per-session key derivation**: On each connection, the sender generates a fresh 256-bit `salt`. Two independent keys are derived via HKDF-SHA256:
  - `enc_key  = HKDF(PSK, salt, info="secure-transfer-enc-v1")`
  - `auth_key = HKDF(PSK, salt, info="secure-transfer-auth-v1")`
  - Separate info strings ensure the two keys are cryptographically independent even though they share the same PSK and salt input.
- **No forward secrecy** (known limitation): compromise of the PSK after the fact allows decryption of any recorded session. This is the key architectural trade-off vs. Approach A's ECDHE.

### Handshake Authentication

The two-message handshake establishes mutual authentication without a PKI:

1. Sender sends `MSG_HELLO`: `salt || sender_nonce`
2. Receiver derives keys, generates `receiver_nonce`, computes:
   `HMAC(auth_key, sender_nonce || receiver_nonce)` and sends in `MSG_HELLO_ACK`
3. Sender verifies the HMAC. Since `auth_key` is derived from the PSK only the real receiver could produce this MAC.

Both nonces prevent replay: a replayed MSG_HELLO_ACK from session N cannot be used in session M because the sender_nonce differs.

### Chunking and Framing

- **Chunk size**: 1 MB, same rationale as Approach A.
- **Frame structure**:
  ```
  [4 bytes: big-endian frame length]
  [1 byte:  message type]
  [8 bytes: chunk_index (big-endian)]
  [12 bytes: AES-GCM nonce]
  [N bytes:  ciphertext]
  [16 bytes: GCM authentication tag]
  ```
- **Nonce construction**: 12 bytes deterministic from (salt, chunk_index). Bytes 0–3 = first 4 bytes of salt XOR'd with chunk_index (big-endian 4 bytes). Bytes 4–7 = bytes 4–7 of salt. Bytes 8–11 = chunk_index raw. Same uniqueness guarantee as Approach A.
- **AAD**: `chunk_index (8 bytes big-endian)` — binds ciphertext to position.

### Resumability

- The receiver writes to `out_path + ".partial"`. If a `.partial` file exists at startup, its size (aligned down to chunk boundary) is reported as a resume offset in `MSG_HELLO_ACK`.
- The sender seeks to the aligned offset and begins sending from that chunk index.
- The partial file is only renamed to the final path after all verification passes.
- **Note**: The resuming session must use the same PSK but will have a *new* salt and thus new keys. The receiver re-hashes already-received bytes to continue the running SHA-256 correctly.

The resume offset is included inside the MSG_HELLO_ACK payload, which is authenticated by HMAC(auth_key, sender_nonce || receiver_nonce). This means the offset is cryptographically signed — a man-in-the-middle cannot forge or modify the resume offset without invalidating the HMAC and causing the sender to abort.

### Exact Algorithms and Parameters

| Parameter | Value |
|---|---|
| Transport | Plain TCP (no TLS) |
| Authentication | HMAC-SHA256 over PSK-derived auth_key |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| PSK length | 256 bits (32 bytes) |
| HKDF salt | 256 bits (32 bytes), fresh per session |
| Chunk AEAD | AES-256-GCM |
| Enc key length | 256 bits |
| GCM nonce | 96 bits, deterministic per session+index |
| GCM tag | 128 bits (full, no truncation) |
| Manifest MAC | HMAC-SHA256 with auth_key |
| End-to-end hash | SHA-256 of full plaintext |

### Threat Model — Approach B

| Threat | CIAA | Mechanism |
|---|---|---|
| **Passive eavesdropper records TCP stream** | C | No plaintext traverses the wire. Chunks are AES-256-GCM encrypted with keys derived from PSK+salt. The PSK never appears on the wire. The salt appears in plaintext, but without the PSK the derived enc_key and auth_key cannot be computed. |
| **Active MITM modifies bytes mid-flight** | I | Per-chunk AES-GCM tag with chunk_index AAD. Any modification, reordering, or truncation causes tag failure. The HMAC-SHA256 manifest at EOF provides a second integrity check. MITM cannot forge a valid manifest without auth_key. |
| **Attacker spoofs sender or receiver** | A | Symmetric: both sender and receiver must know the PSK to compute valid HMACs. A spoofed sender cannot produce a valid `MSG_HELLO_ACK` HMAC. A spoofed receiver cannot decrypt chunks or produce a valid manifest. Proof of PSK knowledge is demonstrated on every connection via the handshake HMAC. |
| **Replay of an earlier valid transfer** | I/A | Each session has a fresh random salt → fresh HKDF-derived keys. Replaying recorded traffic from session N into session M fails at handshake: the sender_nonce differs, so the replayed HELLO_ACK HMAC is invalid. Even if nonces matched, the chunk keys differ because the enc_key is derived from the current session's salt. |
| **Connection drops at 80% transferred** | A | Receiver writes only to `.partial`. Final file path is never touched until full SHA-256 and manifest HMAC verification pass. On reconnect, resume logic picks up from the last complete chunk boundary. |
| **Untrusted intermediary (broker)** | C/I | Approach B's application-layer encryption means a broker that sees only the TCP stream gets only ciphertext and HMAC-authenticated metadata. The enc_key and auth_key are derived from the PSK+salt and never transmitted in plaintext. A broker compromise reveals: the salt (useless without PSK), the ciphertext (useless without enc_key), and the manifest (useless to forge without auth_key). This design would support a store-and-forward broker tier without modification. |

A malicious broker sitting between sender and receiver sees only: the random salt (useless without the PSK), AES-256-GCM ciphertext (useless without enc_key), and HMAC-authenticated framing (unforgeable without auth_key). Neither enc_key nor auth_key ever appear on the wire — they are derived locally on each endpoint from PSK + salt via HKDF. A full broker compromise, including all stored traffic, reveals nothing about the file contents or the PSK.

---

## Meaningful Architectural Differences Between A and B

| Dimension | Approach A | Approach B |
|---|---|---|
| **Security layer** | TLS 1.3 (transport) + AES-GCM (application) | AES-GCM (application only) |
| **Authentication primitive** | X.509 certificates / asymmetric PKI | HMAC-SHA256 / symmetric PSK |
| **Key exchange** | ECDHE ephemeral (forward-secret per session) | HKDF from long-lived PSK (no forward secrecy) |
| **Key distribution problem** | Cert files; CA trust chain | Single symmetric key; out-of-band |
| **Resumability** | Fail-safe (no partial accepted) | Full resume to chunk boundary |
| **Broker-hostile?** | Requires direct TCP connection | Yes — could use an untrusted relay |
| **Dependencies** | Python `ssl` stdlib + `cryptography` | `cryptography` only (no TLS stack) |

---

## Common Design Decisions (Both Approaches)

### Why AES-256-GCM and not ChaCha20-Poly1305?

Both are AEAD ciphers with equivalent security properties. AES-GCM is hardware-accelerated on all modern x86/ARM targets (AES-NI, PMULL), making it faster than ChaCha20-Poly1305 on those platforms. ChaCha20-Poly1305 is preferred on constrained targets without AES hardware. This codebase targets server-class hardware, so AES-GCM is the better practical choice.

### Why not AES-CBC?

AES-CBC provides only confidentiality, not integrity. A padding-oracle attack (POODLE, BEAST) or a cut-and-paste attack can modify ciphertext and the receiver cannot detect it. AES-GCM authenticates every byte. Raw AES-CBC is explicitly prohibited by the assignment spec.

### Why SHA-256 for the end-to-file manifest?

SHA-256 is collision-resistant to 128 bits of security under current cryptanalysis. The file hash in the manifest is additionally authenticated by HMAC-SHA256 (Approach B) or HMAC-SHA256 (Approach A), so an attacker cannot substitute a forged hash without the auth/session key.

### Chunk size rationale (1 MB)

- **Too small** (e.g., 4 KB): high per-chunk overhead from framing, AEAD auth, and syscall cost; thousands of context switches per second.
- **Too large** (e.g., 256 MB): long window before authentication; a MITM gets many round trips to inject before detection; also doesn't fit in RAM on constrained receivers.
- 1 MB is a good balance: ~4,096 chunks for a 4 GB file, authenticated independently, fits in any modern RAM budget.

### Fail-safe on partial transfer

Both implementations follow the same discipline:
1. Write to a temp path (`.partial` or OS-assigned temp).
2. Verify AEAD tags (per chunk), HMAC manifest, chunk count, file size, SHA-256.
3. **Only then** atomically rename to the final output path.
4. On any failure: delete or leave the temp file; never rename to the final path.

This ensures a corrupted, truncated, or tampered transfer never silently produces a file at the expected output location.
