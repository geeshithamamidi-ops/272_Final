#!/usr/bin/env python3
"""
approach-b-encrypted-envelope/receiver.py
Approach B: Pre-Shared-Key Encrypted Envelope over Plain TCP

Usage:
    python3 receiver.py \\
        --out received_file.bin \\
        --port 9444 \\
        --psk-file certs/psk.hex
"""

import argparse
import hashlib
import hmac as hmac_mod
import os
import socket
import struct
import sys
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as crypto_hashes

# ── Constants (must match sender.py) ─────────────────────────────────────────
CHUNK_SIZE: int = 1 * 1024 * 1024
NONCE_SIZE: int = 12
TAG_SIZE: int = 16
SALT_SIZE: int = 32

FRAME_HDR_FMT = "!I"
FRAME_HDR_SIZE = struct.calcsize(FRAME_HDR_FMT)

MSG_HELLO        = b"\x10"
MSG_HELLO_ACK    = b"\x11"
MSG_RESUME_REQ   = b"\x12"
MSG_CHUNK        = b"\x13"
MSG_MANIFEST     = b"\x14"
MSG_ACK          = b"\x15"
MSG_ERR          = b"\xFF"

# Manifest layout: salt(32) || chunk_count(8) || file_size(8) || sha256(32) || hmac(32) = 112 bytes
MANIFEST_BODY_SIZE = 32 + 8 + 8 + 32
MANIFEST_HMAC_SIZE = 32


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
        data = sock.recv(n - len(buf))
        if not data:
            raise EOFError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(data)
    return bytes(buf)


def derive_keys(psk: bytes, salt: bytes) -> tuple[bytes, bytes]:
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


def decrypt_chunk(enc_key: bytes, salt: bytes, chunk_index: int, payload: bytes) -> bytes:
    """
    Decrypt and authenticate one chunk.
    payload = nonce(12) || ciphertext || tag(16)
    """
    from cryptography.exceptions import InvalidTag

    if len(payload) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Encrypted chunk payload too short")

    nonce = payload[:NONCE_SIZE]
    ct_and_tag = payload[NONCE_SIZE:]
    aad = chunk_index.to_bytes(8, "big")

    aesgcm = AESGCM(enc_key)
    try:
        return aesgcm.decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        raise ValueError(
            f"AES-GCM authentication failed for chunk {chunk_index} — "
            "data may have been tampered with"
        )


def load_psk(path: str) -> bytes:
    with open(path) as f:
        hex_str = f.read().strip()
    key = bytes.fromhex(hex_str)
    if len(key) != 32:
        raise ValueError(f"PSK must be 32 bytes, got {len(key)}")
    return key


def check_resume_state(out_path: str) -> int:
    """
    If a partial file exists from a previous run, return its size as the resume offset.
    The offset is aligned down to the nearest chunk boundary.
    """
    partial_path = out_path + ".partial"
    if os.path.exists(partial_path):
        size = os.path.getsize(partial_path)
        aligned = (size // CHUNK_SIZE) * CHUNK_SIZE
        if aligned > 0:
            print(f"[*] Found partial file ({size} bytes), resuming from {aligned}")
            return aligned
    return 0


def perform_handshake(
    sock: socket.socket,
    psk: bytes,
    resume_offset: int,
) -> tuple[bytes, bytes, bytes]:
    """
    1. Receive MSG_HELLO: salt + sender_nonce
    2. Derive keys from PSK + salt
    3. Send MSG_HELLO_ACK: receiver_nonce + HMAC(auth_key, sender_nonce||receiver_nonce)
       + optional resume offset

    Returns: (enc_key, auth_key, salt)
    """
    msg_type, payload = recv_msg(sock)
    if msg_type != MSG_HELLO:
        raise ValueError(f"Expected HELLO, got {msg_type!r}")

    if len(payload) < SALT_SIZE + 32:
        raise ValueError("HELLO payload too short")

    salt = payload[:SALT_SIZE]
    sender_nonce = payload[SALT_SIZE:SALT_SIZE + 32]

    enc_key, auth_key = derive_keys(psk, salt)
    print(f"[✓] Keys derived from PSK  salt={salt.hex()[:16]}…")

    receiver_nonce = os.urandom(32)
    mac = hmac_mod.new(
        auth_key, sender_nonce + receiver_nonce, hashlib.sha256
    ).digest()

    # Append resume offset to ACK if applicable
    ack_payload = receiver_nonce + mac
    if resume_offset > 0:
        ack_payload += resume_offset.to_bytes(8, "big")

    send_msg(sock, MSG_HELLO_ACK, ack_payload)
    print(f"[✓] Handshake complete (authenticated via HMAC-SHA256)")

    return enc_key, auth_key, salt


def receive_transfer(
    sock: socket.socket,
    out_path: str,
    enc_key: bytes,
    auth_key: bytes,
    salt: bytes,
    resume_offset: int,
) -> None:
    partial_path = out_path + ".partial"
    sha256 = hashlib.sha256()
    expected_chunk_index = resume_offset // CHUNK_SIZE
    bytes_received = resume_offset
    t0 = time.monotonic()

    # If resuming, hash the already-received data
    if resume_offset > 0 and os.path.exists(partial_path):
        print(f"[*] Hashing existing partial data ({resume_offset} bytes)…")
        with open(partial_path, "rb") as f:
            while True:
                block = f.read(4 * 1024 * 1024)
                if not block:
                    break
                sha256.update(block)

    try:
        mode = "ab" if resume_offset > 0 else "wb"
        with open(partial_path, mode) as out_f:
            while True:
                msg_type, payload = recv_msg(sock)

                if msg_type == MSG_CHUNK:
                    if len(payload) < 8:
                        raise ValueError("Chunk payload too short for index")

                    chunk_index = int.from_bytes(payload[:8], "big")
                    encrypted = payload[8:]

                    if chunk_index != expected_chunk_index:
                        raise ValueError(
                            f"Chunk index mismatch: expected {expected_chunk_index}, "
                            f"got {chunk_index}"
                        )

                    plaintext = decrypt_chunk(enc_key, salt, chunk_index, encrypted)
                    out_f.write(plaintext)
                    sha256.update(plaintext)
                    bytes_received += len(plaintext)
                    expected_chunk_index += 1

                    elapsed = time.monotonic() - t0
                    mbps = (bytes_received / 1024**2) / max(elapsed, 0.001)
                    print(
                        f"\r    chunk={expected_chunk_index}  "
                        f"{bytes_received / 1024**2:.1f} MB  {mbps:.1f} MB/s",
                        end="",
                        flush=True,
                    )

                elif msg_type == MSG_MANIFEST:
                    print()
                    print("[*] Manifest received. Verifying…")

                    if len(payload) != MANIFEST_BODY_SIZE + MANIFEST_HMAC_SIZE:
                        raise ValueError(f"Manifest wrong size: {len(payload)}")

                    body = payload[:MANIFEST_BODY_SIZE]
                    received_mac = payload[MANIFEST_BODY_SIZE:]

                    # Verify HMAC
                    expected_mac = hmac_mod.new(auth_key, body, hashlib.sha256).digest()
                    if not hmac_mod.compare_digest(expected_mac, received_mac):
                        raise ValueError("Manifest HMAC failed — data may be tampered")

                    # Parse manifest
                    m_salt        = body[0:32]
                    m_chunk_count = int.from_bytes(body[32:40], "big")
                    m_file_size   = int.from_bytes(body[40:48], "big")
                    m_sha256      = body[48:80].hex()

                    if m_salt != salt:
                        raise ValueError("Manifest salt mismatch — replay attack?")
                    if m_chunk_count != expected_chunk_index:
                        raise ValueError(
                            f"Chunk count mismatch: manifest={m_chunk_count}, "
                            f"received={expected_chunk_index}"
                        )
                    if m_file_size != bytes_received:
                        raise ValueError(
                            f"File size mismatch: manifest={m_file_size}, "
                            f"received={bytes_received}"
                        )

                    computed_hash = sha256.hexdigest()
                    if computed_hash != m_sha256:
                        raise ValueError(
                            f"SHA-256 mismatch!\n"
                            f"  Manifest: {m_sha256}\n"
                            f"  Computed: {computed_hash}"
                        )

                    print(f"[✓] SHA-256 verified: {computed_hash}")
                    print(f"[✓] File size verified: {bytes_received} bytes")
                    print(f"[✓] Chunk count: {m_chunk_count}")
                    break

                elif msg_type == MSG_ERR:
                    raise RuntimeError(f"Sender sent error: {payload!r}")
                else:
                    raise ValueError(f"Unknown message type: {msg_type!r}")

        # All verification passed — atomic rename
        os.replace(partial_path, out_path)
        print(f"[✓] File written to: {out_path}")

        elapsed = time.monotonic() - t0
        mbps = (bytes_received / 1024**2) / elapsed
        print(f"[✓] Transfer complete!  {mbps:.2f} MB/s average")

        sidecar = out_path + ".sha256"
        with open(sidecar, "w") as f:
            f.write(f"{sha256.hexdigest()}  {os.path.basename(out_path)}\n")
        print(f"[✓] Hash written to {sidecar}")

        send_msg(sock, MSG_ACK, b"")

    except Exception as exc:
        print(f"\n[✗] Transfer failed: {exc}", file=sys.stderr)
        # Partial file STAYS as .partial for resume — but final path is never written
        if os.path.exists(out_path):
            # Should not happen, but be safe
            quarantine = out_path + ".quarantine"
            os.rename(out_path, quarantine)
            print(f"[*] Quarantined suspect file to {quarantine}", file=sys.stderr)
        try:
            send_msg(sock, MSG_ERR, str(exc).encode()[:256])
        except Exception:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Approach B Receiver: PSK encrypted envelope over plain TCP"
    )
    parser.add_argument("--out", required=True)
    parser.add_argument("--port", type=int, default=9444)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--psk-file", default="../certs/psk.hex")
    args = parser.parse_args()

    psk = load_psk(args.psk_file)

    resume_offset = check_resume_state(args.out)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.bind, args.port))
        server_sock.listen(1)
        print(f"[*] Listening on {args.bind}:{args.port} …")

        conn, addr = server_sock.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"[*] Connection from {addr}")

        try:
            enc_key, auth_key, salt = perform_handshake(conn, psk, resume_offset)
            receive_transfer(conn, args.out, enc_key, auth_key, salt, resume_offset)
        except Exception as exc:
            print(f"[✗] Fatal: {exc}", file=sys.stderr)
            sys.exit(1)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
