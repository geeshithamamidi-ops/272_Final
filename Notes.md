# Running Notes

## Why AES-256-GCM over ChaCha20-Poly1305
Hardware AES-NI acceleration on x86/ARM makes GCM faster on server hardware.
ChaCha20 preferred on constrained devices without AES hardware.

## Why 1 MB chunk size
Too small = high framing overhead. Too large = long window before auth.
1 MB = 4096 chunks for 4 GB, each independently authenticated.

## Why deterministic nonces over random
Random 96-bit nonces have birthday collision risk at scale.
Deterministic (session_id XOR chunk_index) guarantees uniqueness
as long as chunk_index is monotonically increasing.

## Claude disagreement — random nonces
Claude initially proposed os.urandom(12) per chunk. Pushed back because
of birthday bound risk on large files. Switched to deterministic scheme.
See AI_NOTES.md for full discussion.

## Why temp file before rename
Atomic rename ensures partial/corrupt files never appear at final path.
Grader requirement: receiver must fail loudly on any verification failure.