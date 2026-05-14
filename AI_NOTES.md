# AI_NOTES.md — Reflection on Claude Usage

## Which parts did Claude write end-to-end?

**Scaffolding I had Claude generate first, then reviewed:**

- The overall frame-header framing pattern (`struct.pack("!I", length)` + `recv_exactly`) — Claude proposed this immediately and it's a clean, correct pattern for streaming protocols. I kept it verbatim after verifying it.
- The `encrypt_chunk` / `decrypt_chunk` function signatures and the nonce construction strategy (session_id || chunk_index). Claude proposed the first version; I inspected it and revised the XOR-mixing scheme to be more explicit about each byte's origin.
- The manifest body layout: `session_id || chunk_count || file_size || sha256` + `HMAC(auth_key, body)`. Claude proposed this structure. I verified that including `session_id` inside the manifest body (and salt in Approach B's manifest) is necessary to bind the manifest to the session — otherwise a manifest from session N could be grafted onto session M.
- The fail-safe write pattern using `tempfile.mkstemp` + `os.replace`. Claude suggested this immediately and correctly; no modification needed.

**Sections I wrote or heavily modified:**

- The nonce XOR construction. Claude initially proposed `os.urandom(12)` as the nonce, which is fine for most uses but introduces a (very small) nonce-collision risk with a large number of chunks from the same key. I pushed back (see below) and designed the deterministic nonce scheme.
- The resume logic in Approach B. Claude's first draft re-opened the partial file incorrectly (overwriting instead of appending) and did not re-hash the already-received data before continuing the SHA-256 computation. I caught and rewrote this section.
- The architectural comparison table in DESIGN.md. Claude produced a first draft; I revised the "Broker-hostile?" row and the forward-secrecy row to be more precise.
- The two-terminal test harness and all `scripts/` tooling.

---

## Where Claude proposed something wrong or insecure

### Example 1: Random nonces for every chunk (caught and rejected)

Claude's initial `encrypt_chunk` used `os.urandom(12)` to generate a fresh random nonce per chunk. This is common practice and acceptable for low chunk counts, but for a 4 GB file split into 1 MB chunks that's 4,096 nonces per session. Random 96-bit nonces have a ~2^{-32} birthday-bound collision probability at 4,096 chunks — negligible here, but problematic if the same key were ever reused across sessions (which could happen if a user re-sends the same file without regenerating credentials).

**What I did:** Replaced with a deterministic nonce scheme: `salt/session_id || chunk_index`. This guarantees uniqueness as long as chunk_index is monotonically increasing within a session (trivially true in our sequential streaming design) and cross-session uniqueness because the salt/session_id changes every run. The deterministic approach also makes the nonce auditable — a reviewer can inspect the nonce on disk and verify it encodes the expected chunk index.

**Documentation note:** I pushed back in the session and asked Claude to confirm why random nonces could be problematic; it acknowledged the birthday bound correctly and agreed the deterministic scheme was safer. I did not let Claude's "it's fine for this use case" qualifier slide without this explicit conversation.

### Example 2: Missing AAD in first chunk-encryption draft

Claude's first `encrypt_chunk` in Approach A passed `None` as the AAD to `AESGCM.encrypt`. This is valid syntactically — AES-GCM works with empty AAD — but it means the AEAD tag does not authenticate the chunk's position. An attacker who can swap chunk 7 and chunk 8 (both encrypted under the same key) would produce two valid AEAD tags at their respective positions.

**What I did:** Added `aad = session_id + chunk_index.to_bytes(8, "big")` and passed it to both `encrypt` and `decrypt`. This binds each ciphertext to its exact position in the stream; any reordering causes an `InvalidTag` exception at the receiver.

---

## One thing Claude did better than expected

Claude correctly and immediately identified that the receiver must verify the manifest's `session_id` field (Approach A) and `salt` field (Approach B) and compare them against the session-established values, not just verify the HMAC. Without this check, a replayed manifest from a different session (with a different session_id but valid HMAC under a compromised auth_key) could pass the MAC check while the chunk-level AAD would catch the mismatch. Claude added this double-check without being prompted. This is the kind of defence-in-depth reasoning I expected to have to add myself.

---

## One thing Claude did worse than expected

The resume logic in Approach B was Claude's weakest output. The first draft:
1. Opened the partial file in `"wb"` mode even when resuming (wiping existing data).
2. Initialized `sha256 = hashlib.sha256()` fresh without hashing the already-received bytes, so the running digest would be wrong from the first resumed chunk onward.
3. Did not validate that the resume offset was aligned to a chunk boundary before seeking the sender.

All three bugs would have produced a subtly corrupted file that passed the AEAD tag checks on newly-received chunks but would have failed the final SHA-256 comparison (if we were lucky) or silently produced a wrong file (if the SHA-256 check was not present). This reinforced why the assignment requirement to run and test with a real file is non-negotiable — "Claude said the logic is correct" is not a substitute.

---

## Other AI tools used

No other AI tools were used for this submission. All architectural decisions, code review, testing, and documentation were done with Claude Sonnet 4.6 as the sole AI assistant. Claude's outputs were treated as a first draft requiring human review and verification against actual test runs.
