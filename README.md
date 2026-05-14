# Secure 4 GB File Transfer — Assessment Submission

Two architecturally distinct implementations that satisfy **CIAA** (Confidentiality, Integrity, Authenticity, Availability) for transferring a large file over a fully untrusted public network.

| | Approach A | Approach B |
|---|---|---|
| **Name** | mTLS Streaming | PSK Encrypted Envelope |
| **Transport security** | TLS 1.3 record layer + app-layer AES-GCM | Plain TCP; 100% app-layer AES-GCM |
| **Authentication** | X.509 mutual certificates (mTLS) | HMAC-SHA256 over pre-shared key |
| **Key exchange** | TLS 1.3 ECDHE (forward-secret) | HKDF from PSK + fresh random salt |
| **Chunk AEAD** | AES-256-GCM per chunk | AES-256-GCM per chunk |
| **Resumability** | Fail-safe (no silent partial accept) | Full resume via `.partial` file |
| **Directory** | `approach-a-mtls-streaming/` | `approach-b-encrypted-envelope/` |

---

## Quick-Start (under 5 minutes)

### Prerequisites

```bash
pip install cryptography    # only external dependency; stdlib ssl covers TLS
```

Tested on Python 3.10+ with `cryptography >= 41`.

---

### Step 1 — Generate credentials

```bash
# Generate CA + sender/receiver X.509 certs (Approach A)
bash scripts/gen_certs.sh

# Generate 256-bit pre-shared key (Approach B)
python3 scripts/gen_psk.py
```

All credential files land in `certs/`. Never commit them.

---

### Step 2 — Generate test file

```bash
# Full 4 GB test (production run):
python3 scripts/gen_testfile.py --size 4096 --out test_4gb.bin

# Fast smoke-test (32 MB):
python3 scripts/gen_testfile.py --size 32 --out test_32mb.bin
```

A `.sha256` sidecar is written alongside each file for post-transfer verification.

---

### Step 3 — Run Approach A (mTLS streaming)

Open two terminals in the repo root.

**Terminal 1 — Receiver (start first):**
```bash
python3 approach-a-mtls-streaming/receiver.py \
    --out received_a.bin \
    --port 9443 \
    --cert certs/receiver.crt \
    --key  certs/receiver.key \
    --ca   certs/ca.crt
```

**Terminal 2 — Sender:**
```bash
python3 approach-a-mtls-streaming/sender.py \
    --file test_4gb.bin \
    --host 127.0.0.1 --port 9443 \
    --cert certs/sender.crt \
    --key  certs/sender.key \
    --ca   certs/ca.crt
```

**Verify integrity:**
```bash
diff <(cut -d' ' -f1 test_4gb.bin.sha256) <(cut -d' ' -f1 received_a.bin.sha256) \
  && echo "MATCH" || echo "MISMATCH"
```

---

### Step 4 — Run Approach B (PSK encrypted envelope)

**Terminal 1 — Receiver:**
```bash
python3 approach-b-encrypted-envelope/receiver.py \
    --out received_b.bin \
    --port 9444 \
    --psk-file certs/psk.hex
```

**Terminal 2 — Sender:**
```bash
python3 approach-b-encrypted-envelope/sender.py \
    --file test_4gb.bin \
    --host 127.0.0.1 --port 9444 \
    --psk-file certs/psk.hex
```

**Verify integrity:**
```bash
diff <(cut -d' ' -f1 test_4gb.bin.sha256) <(cut -d' ' -f1 received_b.bin.sha256) \
  && echo "MATCH" || echo "MISMATCH"
```

---

## Two-Host Setup

Replace `127.0.0.1` with the receiver's IP in all sender commands. All other flags remain the same. Copy `certs/` to both hosts out-of-band (SCP over a trusted channel, USB, etc.).

---

## File Layout

```
secure-transfer/
├── README.md
├── DESIGN.md
├── AI_NOTES.md
├── scripts/
│   ├── gen_certs.sh        # X.509 cert generation (Approach A)
│   ├── gen_psk.py          # PSK generation (Approach B)
│   └── gen_testfile.py     # Test file generator
├── certs/                  # Generated; never committed
│   ├── ca.{key,crt}
│   ├── sender.{key,crt}
│   ├── receiver.{key,crt}
│   └── psk.hex
├── approach-a-mtls-streaming/
│   ├── sender.py
│   └── receiver.py
└── approach-b-encrypted-envelope/
    ├── sender.py
    └── receiver.py
```

---

## Benchmarks (32 MB loopback, Python 3.12, M-series Mac)

| Approach | Throughput |
|---|---|
| A — mTLS streaming | ~47–52 MB/s |
| B — PSK envelope | ~58–88 MB/s |

**Gap explanation:** Approach A has two encryption layers — TLS record-layer AES-GCM plus application-layer AES-GCM per chunk. Approach B has only the application-layer AEAD, so the CPU does half the symmetric work. Both are I/O-bound on disk-to-disk transfers for large files.

---

## Security Notes

- Never commit `certs/` or `psk.hex` to version control. Add `certs/` and `*.bin` to `.gitignore`.
- Receiver always writes to a `.partial` temp file and only promotes it to the final path after full HMAC/AEAD/SHA-256 verification passes. A dropped connection leaves only the `.partial` file.
- A wrong certificate or wrong PSK causes an immediate hard failure — no partial data is accepted.
