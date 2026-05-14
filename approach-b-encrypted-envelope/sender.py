#!/usr/bin/env python3
"""
approach-b-encrypted-envelope/sender.py
Approach B: Pre-Shared-Key Encrypted Envelope over Plain TCP

Architecture (fundamentally different from Approach A):
  - NO TLS — transport is plain TCP; all security lives at the application layer
  - Sender and receiver share a 256-bit PSK distributed out-of-band (e.g., USB, courier)
  - Two derived keys via HKDF-SHA256:
      enc_key  = HKDF(PSK, salt, info="enc")   — used for AES-256-GCM chunk encryption
      auth_key = HKDF(PSK, salt, info="auth")  — used for HMAC-SHA256 manifest and handshake
  - Fresh random salt per session prevents PSK reuse from producing the same key stream
  - Signed handshake with nonce prevents cross-session replay
  - Resumable: receiver tracks byte offset; sender can seek and restart mid-file

CIAA mapping:
  C — AES-256-GCM per chunk; plaintext never on wire
  I — Per-chunk AEAD tag; HMAC-SHA256 manifest with file hash
  A — HMAC-signed handshake proves knowledge of PSK (symmetric authentication)
  A — TCP retransmission; resume-capable chunked protocol

Usage:
    python3 sender.py \\
        --file path/to/test_4gb.bin \\
        --host 127.0.0.1 --port 9444 \\
        --psk-file certs/psk.hex
"""

import argparse
import hashlib
import hmac as hmac_mod
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as crypto_hashes

# ── Constants ─────────────────────────────────────────────────────────────────
CHUNK_SIZE: int = 1 * 1024 * 1024      # 1 MB — same as Approach A for fair comparison
NONCE_SIZE: int = 12                    # 96-bit GCM nonce
TAG_SIZE: int = 16                      # 128-bit GCM tag
SALT_SIZE: int = 32                     # 256-bit HKDF salt (fresh per session)
NONCE_COUNTER_SIZE: int = 8            # 64-bit chunk counter embedded in nonce

# Framing
FRAME_HDR_FMT = "!I"
FRAME_HDR_SIZE = struct.calcsize(FRAME_HDR_FMT)

# Message types
MSG_HELLO        = b"\x10"   # Sender hello: salt + sender_nonce
MSG_HELLO_ACK    = b"\x11"   # Receiver ack: receiver_nonce + HMAC(auth_key, sender_nonce||receiver_nonce)
MSG_RESUME_REQ   = b"\x12"   # Receiver requests resume at offset
MSG_CHUNK        = b"\x13"   # Encrypted chunk
MSG_MANIFEST     = b"\x14"   # End-of-transfer manifest
MSG_ACK          = b"\x15"   # Final acknowledgement
MSG_ERR          = b"\xFF"   # Error / abort


def send_msg(sock: socket.socket, msg_type: bytes, payload: bytes) -> None:
    frame = msg_type + payload
    header = struct.pack(FRAME_HDR_FMT, len(frame))
    sock.sendall(header + frame)


def recv_msg(sock: socket.socket) -> tuple[bytes, bytes]:
    header = _recv_exactly(sock, FRAME_HDR_SIZE)
    (length,) = struct.unpack(FRAME_HDR_FMT, header)
    if length > 32 * 1024 * 1024:
        raise ValueError(f"Frame length {length} exceeds sanity limit")
    frame = _recv_exactly(sock, length)
    return frame[:1], frame[1:]


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def derive_keys(psk: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derive enc_key and auth_key from PSK via HKDF-SHA256.
    Using separate info strings ensures enc_key and auth_key are independent.
    """
    enc_key = HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secure-transfer-enc-v1",
    ).derive(psk)

    auth_key = HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secure-transfer-auth-v1",
    ).derive(psk)

    return enc_key, auth_key


def make_chunk_nonce(chunk_index: int, salt: bytes) -> bytes:
    """
    Construct a deterministic 96-bit nonce for chunk encryption.
    nonce = first 4 bytes of salt XOR'd with chunk_index (big-endian 4 bytes)
            || next 4 bytes of salt
            || chunk_index as big-endian 4 bytes

    This is collision-free as long as chunk_index is unique within a session,
    and cross-session safety is guaranteed by the fresh salt.
    """
    nonce = bytearray(NONCE_SIZE)
    idx_b = chunk_index.to_bytes(4, "big")
    nonce[0] = salt[0] ^ idx_b[0]
    nonce[1] = salt[1] ^ idx_b[1]
    nonce[2] = salt[2] ^ idx_b[2]
    nonce[3] = salt[3] ^ idx_b[3]
    nonce[4:8] = salt[4:8]
    nonce[8:12] = idx_b  # raw counter in last 4 bytes for readability
    return bytes(nonce)


def encrypt_chunk(enc_key: bytes, salt: bytes, chunk_index: int, plaintext: bytes) -> bytes:
    """
    Encrypt one chunk with AES-256-GCM.
    AAD = chunk_index (8 bytes big-endian) — binds ciphertext to its position.
    """
    nonce = make_chunk_nonce(chunk_index, salt)
    aad = chunk_index.to_bytes(8, "big")
    aesgcm = AESGCM(enc_key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct_and_tag  # 12 + len(plaintext) + 16


def load_psk(path: str) -> bytes:
    with open(path) as f:
        hex_str = f.read().strip()
    key = bytes.fromhex(hex_str)
    if len(key) != 32:
        raise ValueError(f"PSK must be 32 bytes (64 hex chars), got {len(key)}")
    return key


def perform_handshake(
    sock: socket.socket,
    auth_key: bytes,
    salt: bytes,
) -> int:
    """
    Two-message authenticated handshake.
    1. Sender → Receiver: MSG_HELLO | salt | sender_nonce
    2. Receiver → Sender: MSG_HELLO_ACK | receiver_nonce | HMAC(auth_key, sender_nonce||receiver_nonce)
       plus optional MSG_RESUME_REQ | offset(8)

    Returns: byte offset to resume from (0 = fresh start)
    """
    sender_nonce = os.urandom(32)

    # Step 1: Send hello
    send_msg(sock, MSG_HELLO, salt + sender_nonce)
    print(f"[*] Handshake sent  salt={salt.hex()[:16]}…")

    # Step 2: Receive ack
    msg_type, payload = recv_msg(sock)
    if msg_type == MSG_ERR:
        raise RuntimeError(f"Receiver rejected handshake: {payload!r}")
    if msg_type != MSG_HELLO_ACK:
        raise ValueError(f"Expected HELLO_ACK, got {msg_type!r}")

    if len(payload) < 32 + 32:
        raise ValueError("HELLO_ACK payload too short")

    receiver_nonce = payload[:32]
    received_mac = payload[32:64]

    # Verify receiver's HMAC — proves they hold the same PSK
    expected_mac = hmac_mod.new(
        auth_key, sender_nonce + receiver_nonce, hashlib.sha256
    ).digest()
    if not hmac_mod.compare_digest(expected_mac, received_mac):
        raise ValueError("Handshake HMAC mismatch — receiver authentication failed")

    print("[✓] Receiver authenticated via HMAC")

    # Check for resume request
    resume_offset = 0
    if len(payload) >= 64 + 8:
        resume_offset = int.from_bytes(payload[64:72], "big")
        if resume_offset > 0:
            print(f"[*] Resume requested at offset {resume_offset} bytes")

    return resume_offset


def transfer(
    sock: socket.socket,
    file_path: str,
    enc_key: bytes,
    auth_key: bytes,
    salt: bytes,
    resume_offset: int = 0,
) -> None:
    file_size = os.path.getsize(file_path)
    sha256_full = hashlib.sha256()
    t0 = time.monotonic()

    # Compute SHA-256 of the *entire* file (including skipped prefix on resume)
    print(f"[*] Computing full-file SHA-256 (streaming)…")
    sha_start = time.monotonic()
    with open(file_path, "rb") as f:
        while True:
            block = f.read(4 * 1024 * 1024)
            if not block:
                break
            sha256_full.update(block)
    print(f"    Done in {time.monotonic() - sha_start:.1f}s")

    # Determine starting chunk index from resume offset
    start_chunk = resume_offset // CHUNK_SIZE
    actual_offset = start_chunk * CHUNK_SIZE  # align to chunk boundary

    chunk_index = start_chunk
    bytes_sent = actual_offset
    t0 = time.monotonic()

    print(f"[*] Transfer start  file={file_path}  ({file_size / 1024**3:.3f} GB)")
    if actual_offset > 0:
        print(f"    Resuming from chunk {start_chunk} (offset {actual_offset})")

    with open(file_path, "rb") as f:
        f.seek(actual_offset)
        while True:
            plaintext = f.read(CHUNK_SIZE)
            if not plaintext:
                break

            ciphertext = encrypt_chunk(enc_key, salt, chunk_index, plaintext)

            # MSG_CHUNK | chunk_index(8) | ciphertext
            payload = chunk_index.to_bytes(8, "big") + ciphertext
            send_msg(sock, MSG_CHUNK, payload)

            bytes_sent += len(plaintext)
            chunk_index += 1
            pct = bytes_sent / file_size * 100
            elapsed = time.monotonic() - t0
            mbps = ((bytes_sent - actual_offset) / 1024**2) / max(elapsed, 0.001)
            print(f"\r    {pct:5.1f}%  chunk={chunk_index}  {mbps:.1f} MB/s", end="", flush=True)

    print()
    file_hash = sha256_full.hexdigest()
    total_chunks = chunk_index
    print(f"[*] All chunks sent.  SHA-256={file_hash}  chunks={total_chunks}")

    # Build and send manifest
    manifest_body = (
        salt
        + total_chunks.to_bytes(8, "big")
        + file_size.to_bytes(8, "big")
        + bytes.fromhex(file_hash)
    )
    mac = hmac_mod.new(auth_key, manifest_body, hashlib.sha256).digest()
    send_msg(sock, MSG_MANIFEST, manifest_body + mac)
    print("[*] Manifest sent. Awaiting acknowledgement…")

    msg_type, payload = recv_msg(sock)
    if msg_type == MSG_ACK:
        elapsed = time.monotonic() - t0
        transferred = bytes_sent - actual_offset
        mbps = (transferred / 1024**2) / elapsed
        gbps = mbps / 1024
        print(f"[✓] Transfer complete!")
        print(f"    ┌─────────────────────────────────┐")
        print(f"    │  Bytes sent   : {transferred / (1024**3):.3f} GB          │")
        print(f"    │  Time elapsed : {elapsed:.1f}s               │")
        print(f"    │  Throughput   : {mbps:.2f} MB/s ({gbps:.3f} GB/s) │")
        print(f"    │  Chunks sent  : {chunk_index}                  │")
        print(f"    └─────────────────────────────────┘")
    else:
        print(f"[✗] Receiver error: {payload!r}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Approach B Sender: PSK encrypted envelope over plain TCP"
    )
    parser.add_argument("--file", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9444)
    parser.add_argument("--psk-file", default="../certs/psk.hex",
                        help="Path to PSK hex file")
    args = parser.parse_args()

    psk = load_psk(args.psk_file)
    salt = os.urandom(SALT_SIZE)  # fresh per session
    enc_key, auth_key = derive_keys(psk, salt)
    print(f"[*] Derived keys from PSK  salt={salt.hex()[:16]}…")

    print(f"[*] Connecting to {args.host}:{args.port} …")
    sock = socket.create_connection((args.host, args.port), timeout=60)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        resume_offset = perform_handshake(sock, auth_key, salt)
        transfer(sock, args.file, enc_key, auth_key, salt, resume_offset)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
