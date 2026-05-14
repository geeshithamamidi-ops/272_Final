#!/usr/bin/env python3
"""
gen_testfile.py — Generate a test file for transfer benchmarking.

Usage:
    python3 scripts/gen_testfile.py --size 4096 --out test_4gb.bin
    python3 scripts/gen_testfile.py --size 1    --out test_1mb.bin   # quick smoke-test

Output: file + a .sha256 sidecar for post-transfer verification.
"""

import argparse
import hashlib
import os
import sys
import time


CHUNK = 4 * 1024 * 1024  # 4 MB write chunks


def generate(path: str, size_mb: int, random: bool) -> str:
    total_bytes = size_mb * 1024 * 1024
    written = 0
    sha = hashlib.sha256()

    print(f"[*] Generating {'random' if random else 'zero'} file: {path} ({size_mb} MB)")
    t0 = time.monotonic()

    with open(path, "wb") as f:
        while written < total_bytes:
            remaining = total_bytes - written
            chunk_size = min(CHUNK, remaining)
            data = os.urandom(chunk_size) if random else b"\x00" * chunk_size
            f.write(data)
            sha.update(data)
            written += chunk_size
            pct = written / total_bytes * 100
            print(f"\r    {pct:5.1f}%  {written // (1024*1024)} MB / {size_mb} MB", end="", flush=True)

    elapsed = time.monotonic() - t0
    digest = sha.hexdigest()
    print(f"\n[*] Done in {elapsed:.1f}s  ({size_mb / elapsed:.1f} MB/s)")
    print(f"[*] SHA-256: {digest}")

    # Write sidecar
    sidecar = path + ".sha256"
    with open(sidecar, "w") as f:
        f.write(f"{digest}  {os.path.basename(path)}\n")
    print(f"[*] Hash saved to {sidecar}")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=4096, help="File size in MB (default 4096 = 4 GB)")
    parser.add_argument("--out", default="test_4gb.bin", help="Output path")
    parser.add_argument("--zeros", action="store_true", help="Use zero bytes instead of random (faster)")
    args = parser.parse_args()

    generate(args.out, args.size, random=not args.zeros)


if __name__ == "__main__":
    main()
