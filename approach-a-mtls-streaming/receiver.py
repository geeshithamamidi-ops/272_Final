#!/usr/bin/env python3
"""
approach-a-mtls-streaming/receiver.py
Approach A: Mutually-Authenticated TLS Streaming with Per-Chunk AES-GCM

Usage:
    python3 receiver.py \\
        --out received_file.bin \\
        --port 9443 \\
        --cert certs/receiver.crt --key certs/receiver.key \\
        --ca   certs/ca.crt \\
        --session-key <32-byte-hex>   # must match sender's key if pre-shared
"""

import argparse
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys
import tempfile
import time

# ── Constants (must match sender.py) ─────────────────────────────────────────
CHUNK_SIZE: int = 1 * 1024 * 1024
NONCE_SIZE: int = 12
TAG_SIZE: int = 16
SESSION_ID_SIZE: int = 16
PROTOCOL_VERSION: int = 1

FRAME_HEADER_FMT = "!I"
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FMT)

TYPE_CHUNK    = b"\x01"
TYPE_MANIFEST = b"\x02"
TYPE_ABORT    = b"\xFF"

# Manifest body layout (bytes):
#   session_id(16) || chunk_count(8) || file_size(8) || sha256(32) || hmac(32)
MANIFEST_BODY_SIZE = 16 + 8 + 8 + 32
MANIFEST_HMAC_SIZE = 32
MANIFEST_TOTAL_SIZE = 1 + MANIFEST_BODY_SIZE + MANIFEST_HMAC_SIZE  # includes TYPE byte


def recv_exactly(sock: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly n bytes from TLS socket; raises EOFError on connection close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: ssl.SSLSocket) -> bytes:
    """Receive one length-prefixed frame."""
    header = recv_exactly(sock, FRAME_HEADER_SIZE)
    (length,) = struct.unpack(FRAME_HEADER_FMT, header)
    if length > 64 * 1024 * 1024:  # sanity cap: 64 MB
        raise ValueError(f"Frame length {length} exceeds sanity limit")
    return recv_exactly(sock, length)


def decrypt_chunk(
    key: bytes,
    session_id: bytes,
    chunk_index: int,
    ciphertext_with_tag: bytes,
) -> bytes:
    """
    Decrypt and authenticate one chunk.
    Raises cryptography.exceptions.InvalidTag on any tampering.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(ciphertext_with_tag) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short to contain nonce and tag")

    nonce = ciphertext_with_tag[:NONCE_SIZE]
    ct_and_tag = ciphertext_with_tag[NONCE_SIZE:]

    aad = session_id + chunk_index.to_bytes(8, "big")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, aad)


def receive_transfer(
    sock: ssl.SSLSocket,
    out_path: str,
    session_key: bytes,
    session_id: bytes,
) -> None:
    """Receive, decrypt, and verify the streamed file."""
    sha256 = hashlib.sha256()
    expected_chunk_index = 0
    bytes_received = 0
    t0 = time.monotonic()

    # Write to a temp file in the same directory; atomic rename on success
    out_dir = os.path.dirname(os.path.abspath(out_path))
    tmp_fd, tmp_path = tempfile.mkstemp(dir=out_dir, prefix=".partial_")

    print(f"[*] Receiving to temp file: {tmp_path}")

    try:
        with os.fdopen(tmp_fd, "wb") as out_f:
            while True:
                frame = recv_frame(sock)
                frame_type = frame[:1]

                if frame_type == TYPE_CHUNK:
                    # Frame: TYPE(1) || session_id(16) || chunk_index(8) || encrypted_chunk
                    if len(frame) < 1 + 16 + 8:
                        raise ValueError("Chunk frame too short")
                    frame_session_id = frame[1:17]
                    frame_chunk_index = int.from_bytes(frame[17:25], "big")
                    encrypted_chunk = frame[25:]

                    # Authenticate session binding
                    if frame_session_id != session_id:
                        raise ValueError(
                            f"Session ID mismatch: expected {session_id.hex()}, "
                            f"got {frame_session_id.hex()}"
                        )

                    # Authenticate chunk ordering (prevents reorder/replay)
                    if frame_chunk_index != expected_chunk_index:
                        raise ValueError(
                            f"Chunk index mismatch: expected {expected_chunk_index}, "
                            f"got {frame_chunk_index}"
                        )

                    plaintext = decrypt_chunk(
                        session_key, session_id, frame_chunk_index, encrypted_chunk
                    )
                    out_f.write(plaintext)
                    sha256.update(plaintext)
                    bytes_received += len(plaintext)
                    expected_chunk_index += 1

                    elapsed = time.monotonic() - t0
                    mbps = (bytes_received / (1024**2)) / max(elapsed, 0.001)
                    print(
                        f"\r    chunk={expected_chunk_index}  "
                        f"{bytes_received / (1024**2):.1f} MB  {mbps:.1f} MB/s",
                        end="",
                        flush=True,
                    )

                elif frame_type == TYPE_MANIFEST:
                    print()
                    print("[*] Manifest received. Verifying…")

                    # Frame: TYPE(1) || body(64) || hmac(32)
                    if len(frame) != 1 + MANIFEST_BODY_SIZE + MANIFEST_HMAC_SIZE:
                        raise ValueError(
                            f"Manifest frame wrong size: {len(frame)}"
                        )

                    body = frame[1 : 1 + MANIFEST_BODY_SIZE]
                    received_mac = frame[1 + MANIFEST_BODY_SIZE:]

                    # Verify HMAC
                    expected_mac = hmac.new(session_key, body, hashlib.sha256).digest()
                    if not hmac.compare_digest(expected_mac, received_mac):
                        raise ValueError("Manifest HMAC verification failed — tampering detected")

                    # Parse manifest fields
                    m_session_id  = body[0:16]
                    m_chunk_count = int.from_bytes(body[16:24], "big")
                    m_file_size   = int.from_bytes(body[24:32], "big")
                    m_sha256      = body[32:64].hex()

                    if m_session_id != session_id:
                        raise ValueError("Manifest session ID mismatch")
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

                    # Verify end-to-end SHA-256
                    computed_hash = sha256.hexdigest()
                    if computed_hash != m_sha256:
                        raise ValueError(
                            f"SHA-256 mismatch!\n"
                            f"  Manifest:  {m_sha256}\n"
                            f"  Computed:  {computed_hash}"
                        )

                    print(f"[✓] SHA-256 verified: {computed_hash}")
                    print(f"[✓] File size verified: {bytes_received} bytes")
                    print(f"[✓] Chunk count verified: {m_chunk_count}")
                    break  # success

                elif frame_type == TYPE_ABORT:
                    raise RuntimeError("Sender sent ABORT signal")

                else:
                    raise ValueError(f"Unknown frame type: {frame_type!r}")

        # Atomic rename — only happens after full verification
        os.replace(tmp_path, out_path)
        print(f"[✓] File written to: {out_path}")

        elapsed = time.monotonic() - t0
        mbps = (bytes_received / (1024**2)) / elapsed
        print(f"[✓] Transfer complete!  {mbps:.2f} MB/s average")

        # Write hash sidecar
        sidecar = out_path + ".sha256"
        with open(sidecar, "w") as f:
            f.write(f"{sha256.hexdigest()}  {os.path.basename(out_path)}\n")
        print(f"[✓] Hash written to: {sidecar}")

        # Send ACK
        sock.sendall(b"ACK\x00")

    except Exception as exc:
        print(f"\n[✗] Transfer failed: {exc}", file=sys.stderr)
        # Quarantine: delete temp file, do NOT rename to final path
        try:
            os.unlink(tmp_path)
            print("[*] Partial temp file deleted (fail-safe)", file=sys.stderr)
        except FileNotFoundError:
            pass
        try:
            sock.sendall(b"ERR\x00")
        except Exception:
            pass
        raise


def build_ssl_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """Configure TLS 1.3 mTLS context for the receiver (server side)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED  # require client cert
    return ctx


def verify_peer_cn(sock: ssl.SSLSocket, expected_cn: str) -> None:
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
        description="Approach A Receiver: mTLS streaming with AES-256-GCM chunks"
    )
    parser.add_argument("--out", required=True, help="Path to write received file")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--cert", default="../certs/receiver.crt")
    parser.add_argument("--key",  default="../certs/receiver.key")
    parser.add_argument("--ca",   default="../certs/ca.crt")
    parser.add_argument("--session-key", help="32-byte hex pre-shared session key")
    parser.add_argument("--sender-cn", default="sender",
                        help="Expected CN in sender's certificate")
    args = parser.parse_args()

    if args.session_key:
        session_key_pre = bytes.fromhex(args.session_key)
        if len(session_key_pre) != 32:
            print("[✗] --session-key must be 64 hex chars (32 bytes)", file=sys.stderr)
            sys.exit(1)
    else:
        session_key_pre = None

    ctx = build_ssl_context(args.cert, args.key, args.ca)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.bind, args.port))
        server_sock.listen(1)
        print(f"[*] Listening on {args.bind}:{args.port} …")

        conn, addr = server_sock.accept()
        print(f"[*] Connection from {addr}")

        tls_conn = ctx.wrap_socket(conn, server_side=True)
        try:
            print(f"[✓] TLS {tls_conn.version()} established")
            verify_peer_cn(tls_conn, args.sender_cn)

            # Derive or receive session key
            if session_key_pre is None:
                # Receive the session key sent by sender over the authenticated TLS tunnel
                session_key = recv_exactly(tls_conn, 32)
                print("[*] Received session key over authenticated TLS channel")
            else:
                session_key = session_key_pre
                # Sender will still send a session key; read and discard or verify
                sent_key = recv_exactly(tls_conn, 32)
                if sent_key != session_key:
                    raise ValueError("Pre-shared session key mismatch with sender's key")
                print("[*] Pre-shared session key verified")

            # Receive session_id from sender
            session_id = recv_exactly(tls_conn, SESSION_ID_SIZE)
            print(f"[*] Session ID: {session_id.hex()[:16]}…")

            receive_transfer(tls_conn, args.out, session_key, session_id)

        except Exception as exc:
            print(f"[✗] Fatal: {exc}", file=sys.stderr)
            sys.exit(1)
        finally:
            tls_conn.close()


if __name__ == "__main__":
    main()
