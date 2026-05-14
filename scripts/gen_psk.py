#!/usr/bin/env python3
"""
gen_psk.py — Generate a 256-bit pre-shared key for Approach B.
The PSK is written as a hex string to a file; distribute it out-of-band.

Usage: python3 scripts/gen_psk.py [--out PATH]
"""

import argparse
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a 256-bit PSK for Approach B")
    parser.add_argument("--out", default="certs/psk.hex",
                        help="Output path for the PSK hex file (default: certs/psk.hex)")
    args = parser.parse_args()

    out_path = args.out
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)

    psk_bytes = os.urandom(32)  # 256-bit key
    psk_hex = psk_bytes.hex()

    with open(out_path, "w") as f:
        f.write(psk_hex + "\n")

    # Restrict permissions to owner-read only
    os.chmod(out_path, 0o600)

    print(f"[*] PSK written to {out_path} (600 permissions)")
    print(f"    Key length: {len(psk_bytes) * 8} bits")
    print(f"    Distribute this file out-of-band to both sender and receiver.")


if __name__ == "__main__":
    main()
