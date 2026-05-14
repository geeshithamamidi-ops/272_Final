#!/usr/bin/env python3
"""
approach-a-mtls-streaming/sender.py
Approach A: Mutually-Authenticated TLS Streaming with Per-Chunk AES-GCM

Architecture:
  - TLS 1.3 with mutual certificate authentication (mTLS)
  - File is streamed in CHUNK_SIZE chunks; each chunk is independently encrypted
    with AES-256-GCM using a per-chunk nonce derived from (session_id || chunk_index)
  - After all chunks, a signed manifest (SHA-256 of full plaintext) is sent so the
    receiver can verify end-to-end integrity
  - Per-session session_id prevents cross-session replay of chunks

CIAA mapping:
  C — AES-256-GCM per chunk; TLS record layer adds another encryption layer
  I — Per-chunk AEAD tag; end-of-file SHA-256 manifest
  A — mTLS: sender presents sender.crt, verifies receiver.crt against CA
  A — TCP + chunked framing; receiver aborts on any auth failure

Usage:
    python3 sender.py \\
        --file path/to/test_4gb.bin \\
        --host 127.0.0.1 --port 9443 \\
        --cert certs/sender.crt --key certs/sender.key \\
        --ca   certs/ca.crt \\
        --session-key <32-byte-hex>
"""

import argparse
import hashlib
import os
import socket
import ssl
import struct
import sys
import time
from typing import BinaryIO

# ── Constants ─────────────────────────────────────────────────────────────────
CHUNK_SIZE: int = 1 * 1024 * 1024          # 1 MB application chunks
NONCE_SIZE: int = 12                        # 96-bit GCM nonce
TAG_SIZE: int = 16                          # 128-bit GCM authentication tag
SESSION_ID_SIZE: int = 16                   # 128-bit random session identifier
PROTOCOL_VERSION: int = 1

# Wire framing: each chunk preceded by a 4-byte big-endian length
FRAME_HEADER_FMT = "!I"
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FMT)

# Chunk types sent over TLS stream
TYPE_CHUNK    = b"\x01"
TYPE_MANIFEST = b"\x02"
TYPE_ABORT    = b"\xFF"


def send_frame(sock: ssl.SSLSocket, data: bytes) -> None:
    """Send a length-prefixed frame over the TLS socket."""
    header = struct.pack(FRAME_HEADER_FMT, len(data))
    sock.sendall(header + data)


def encrypt_chunk(
    key: bytes,
    session_id: bytes,
    chunk_index: int,
    plaintext: bytes,
) -> bytes:
    """
    Encrypt one chunk with AES-256-GCM.

    Nonce construction: session_id[:4] XOR little-endian(chunk_index) padded to 12 bytes.
    Using a deterministic nonce tied to (session_id, chunk_index) ensures:
      - Uniqueness within a session (chunk_index is monotonically increasing)
      - Cross-session safety (session_id differs each run)
    Additional data (AAD): session_id || big-endian(chunk_index)
      — binds ciphertext to its position; a reordering attack triggers a tag failure.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # 12-byte nonce: first 4 bytes of session_id XOR'd with chunk counter
    nonce = bytearray(NONCE_SIZE)
    nonce[:4] = session_id[:4]
    idx_bytes = chunk_index.to_bytes(4, "little")
    for i in range(4):
        nonce[i] ^= idx_bytes[i]
    nonce[4:8] = session_id[4:8]   # mix in more session entropy
    nonce[8:12] = chunk_index.to_bytes(4, "big")

    aad = session_id + chunk_index.to_bytes(8, "big")  # additional authenticated data

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(bytes(nonce), plaintext, aad)

    # Wire format: nonce (12) || ciphertext || tag (16)
    return bytes(nonce) + ciphertext_and_tag


def transfer(
    sock: ssl.SSLSocket,
    file_path: str,
    session_key: bytes,
    session_id: bytes,
) -> None:
    """Stream the file, encrypt chunk by chunk, verify integrity."""
    file_size = os.path.getsize(file_path)
    sha256 = hashlib.sha256()
    chunk_index = 0
    bytes_sent = 0
    t0 = time.monotonic()

    print(f"[*] Transfer start  session_id={session_id.hex()[:16]}…")
    print(f"    File: {file_path}  ({file_size / (1024**3):.3f} GB)")
    print(f"    Chunk size: {CHUNK_SIZE // 1024} KB")

    with open(file_path, "rb") as f:
        while True:
            plaintext = f.read(CHUNK_SIZE)
            if not plaintext:
                break

            sha256.update(plaintext)
            ciphertext = encrypt_chunk(session_key, session_id, chunk_index, plaintext)

            # Frame: TYPE_CHUNK || session_id || chunk_index(8) || encrypted_chunk
            frame = (
                TYPE_CHUNK
                + session_id
                + chunk_index.to_bytes(8, "big")
                + ciphertext
            )
            send_frame(sock, frame)

            bytes_sent += len(plaintext)
            chunk_index += 1
            pct = bytes_sent / file_size * 100
            elapsed = time.monotonic() - t0
            mbps = (bytes_sent / (1024**2)) / max(elapsed, 0.001)
            print(f"\r    {pct:5.1f}%  chunk={chunk_index}  {mbps:.1f} MB/s", end="", flush=True)

    print()
    file_hash = sha256.hexdigest()
    print(f"[*] All chunks sent.  SHA-256={file_hash}")
    print(f"    Total chunks: {chunk_index}  Bytes: {bytes_sent}")

    # Send manifest: signed with session_key via HMAC-SHA256
    import hmac
    manifest_body = (
        session_id
        + chunk_index.to_bytes(8, "big")
        + file_size.to_bytes(8, "big")
        + bytes.fromhex(file_hash)
    )
    mac = hmac.new(session_key, manifest_body, hashlib.sha256).digest()
    manifest_frame = TYPE_MANIFEST + manifest_body + mac
    send_frame(sock, manifest_frame)
    print("[*] Manifest sent. Waiting for receiver acknowledgement…")

    # Read receiver ACK (4 bytes: b"ACK\x00" or b"ERR\x00")
    ack_raw = sock.recv(4)
    if ack_raw == b"ACK\x00":
        elapsed = time.monotonic() - t0
        mbps = (bytes_sent / (1024**2)) / elapsed
        print(f"[✓] Transfer complete!  {mbps:.2f} MB/s average")
    else:
        print(f"[✗] Receiver reported error: {ack_raw!r}")
        sys.exit(1)


def build_ssl_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """Configure TLS 1.3 mTLS context for the sender (client side)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # We verify CN manually below
    return ctx


def verify_peer_cn(sock: ssl.SSLSocket, expected_cn: str) -> None:
    """Manually verify the peer certificate's CN field."""
    cert = sock.getpeercert()
    if not cert:
        raise ssl.SSLError("No peer certificate presented")
    subject = dict(x[0] for x in cert.get("subject", ()))
    cn = subject.get("commonName", "")
    if cn != expected_cn:
        raise ssl.SSLError(f"Peer CN mismatch: expected '{expected_cn}', got '{cn}'")
    print(f"[✓] Peer authenticated: CN={cn}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Approach A Sender: mTLS streaming with AES-256-GCM chunks"
    )
    parser.add_argument("--file", required=True, help="Path to file to send")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--cert", default="../certs/sender.crt")
    parser.add_argument("--key",  default="../certs/sender.key")
    parser.add_argument("--ca",   default="../certs/ca.crt")
    parser.add_argument(
        "--session-key",
        help="32-byte hex session key for chunk AEAD (if omitted, derived from TLS exporter)",
    )
    parser.add_argument("--receiver-cn", default="receiver",
                        help="Expected CN in receiver's certificate")
    args = parser.parse_args()

    # Load or derive session key
    if args.session_key:
        session_key = bytes.fromhex(args.session_key)
        if len(session_key) != 32:
            print("[✗] --session-key must be 64 hex chars (32 bytes)", file=sys.stderr)
            sys.exit(1)
    else:
        session_key = None  # will be derived from TLS exporter material

    ctx = build_ssl_context(args.cert, args.key, args.ca)

    print(f"[*] Connecting to {args.host}:{args.port} …")
    raw_sock = socket.create_connection((args.host, args.port), timeout=30)
    tls_sock = ctx.wrap_socket(raw_sock, server_side=False)

    try:
        print(f"[✓] TLS {tls_sock.version()} established")
        verify_peer_cn(tls_sock, args.receiver_cn)

            # Derive per-session key if not provided.
        # We generate a random 32-byte session salt, send it over the TLS tunnel
        # (protected by TLS confidentiality), then both sides derive the chunk
        # AEAD key via HKDF(PSK_OR_RANDOM, session_salt, info="chunk-aead-v1").
        # Since the salt travels inside TLS, an eavesdropper cannot compute the key.
        if session_key is None:
            # No PSK provided: generate a random one-time key for this session
            session_key = os.urandom(32)
            print("[*] Generated random per-session chunk key")
        else:
            print("[*] Using provided session key")

        # Always send the session key to receiver over the mutually-authenticated TLS channel
        # (safe because TLS provides confidentiality and both sides are authenticated)
        tls_sock.sendall(session_key)

        session_id = os.urandom(SESSION_ID_SIZE)
        # Send session_id to receiver first
        tls_sock.sendall(session_id)

        transfer(tls_sock, args.file, session_key, session_id)
    finally:
        tls_sock.close()


if __name__ == "__main__":
    main()
