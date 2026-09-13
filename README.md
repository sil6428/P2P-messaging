# P2P Messaging

[![Quality checks](https://github.com/sil6428/P2P-messaging/actions/workflows/quality.yml/badge.svg)](https://github.com/sil6428/P2P-messaging/actions/workflows/quality.yml)

> **Educational work in progress.** This project now supports a small encrypted
> peer-to-peer demo. It is not independently audited or ready for sensitive use.

A Python learning project for direct messages between two explicitly trusted
peers. There is no central message server: one peer listens on a TCP endpoint and
the other connects directly using a shared public peer card.

## What works

- password-protected Ed25519 and X25519 device identities;
- self-signed public peer cards with human-checkable fingerprints;
- a local contact book that tracks whether each imported card's fingerprint was
  verified out-of-band, and keeps unverified contacts out of the trust list;
- ChaCha20-Poly1305 message encryption with authenticated routing metadata;
- Ed25519 envelope signatures and encrypted delivery acknowledgements;
- an interactive two-way `chat` session, alongside the one-shot `send`/`listen`
  commands;
- an encrypted local message history, locked by its own password;
- attachment digest references (filename, size, SHA-256) bound into a message
  so a file moved out-of-band can be verified and quarantined on mismatch;
- 64 KiB frame limits, 4 KiB plaintext limits, recipient checks, persistent
  replay rejection, per-peer rate limiting, and per-connection read timeouts;
- tests for tampering, expired messages, wrong recipients, unknown peers,
  oversized frames, replay attempts, rate limits, malformed/fuzzed envelopes,
  and end-to-end delivery.

Messages are end-to-end encrypted between the two demo peers, but the custom
protocol does **not** provide forward secrecy, automatic key rotation, NAT
traversal, multi-device support, or independent security assurance. Read
[the protocol](docs/PROTOCOL.md) and [threat model](docs/THREAT_MODEL.md) before
using it.

## Install

Requires Python 3.11 or newer.

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

python -m pip install -e ".[dev]"
```

## Try two peers locally

The commands below use separate identities and ports so the complete exchange
can run on one computer. Enter a different password for each identity and do not
commit either `*.identity.json` file.

```bash
# Create Alice's private identity and public card
secure-messaging identity init --name Alice \
  --identity alice.identity.json --card alice.peer.json \
  --endpoint 127.0.0.1:8765

# Create Bob's private identity and public card
secure-messaging identity init --name Bob \
  --identity bob.identity.json --card bob.peer.json \
  --endpoint 127.0.0.1:8766
```

Compare each card's fingerprint with its owner through a separate trusted
channel. A self-signature only proves the card was not edited after creation; it
does not prove the owner's identity.

Start Bob's listener in terminal 1:

```bash
secure-messaging listen --identity bob.identity.json \
  --trust alice.peer.json --database bob-state.db \
  --host 127.0.0.1 --port 8766
```

Send from Alice in terminal 2:

```bash
secure-messaging send --identity alice.identity.json \
  --peer bob.peer.json --message "hello Bob"
```

Bob sees the plaintext only after the trusted-sender, signature, recipient,
timestamp, authenticated-encryption, and replay checks pass. Alice accepts
delivery only after decrypting Bob's matching acknowledgement.

## Development checks

```bash
ruff check src tests
pytest -q
```

The optional local status endpoint remains available with
`secure-messaging serve` and reports the project's development limits.

The current **63-test** suite covers the CLI and status endpoint, identity
protection, envelope signatures, authenticated encryption, expiration,
recipient validation, replay persistence, bounded frames, acknowledgements,
end-to-end local delivery, contact verification state, encrypted local
history, attachment digest binding, per-peer rate limiting, and fuzzed
envelope parsing.

## Contact verification, history, and attachments

```bash
# Import a peer card (unverified until you compare fingerprints out-of-band)
secure-messaging contacts import bob.peer.json --contacts contacts.db
secure-messaging contacts verify "AB12 CD34" --contacts contacts.db
secure-messaging contacts list --contacts contacts.db

# Listen using verified contacts instead of --trust files
secure-messaging listen --identity alice.identity.json --contacts contacts.db \
  --database alice-state.db --history alice-history.db

# Two-way interactive session instead of one-shot send/listen
secure-messaging chat --identity alice.identity.json --peer bob.peer.json

# Bind a file's digest to a message, then verify it after it arrives out-of-band
secure-messaging send --identity alice.identity.json --peer bob.peer.json \
  --message "see attached" --attach report.pdf
secure-messaging verify-attachment reference.json downloaded-report.pdf
```

## Collaborating

[CONTRIBUTING.md](CONTRIBUTING.md) tracks what is still open for another
contributor: failure recovery under full-disk and mid-transfer disconnect
conditions, structured local audit events, and full integration with the
separate [Secure File Transfer](https://github.com/sil6428/secure-file-transfer)
project (this repository only carries the digest reference, not the file
bytes). The current code provides interfaces and tests those pieces can build
on without pretending the project is finished.

## License

All rights reserved. The code may be shared with authorized portfolio reviewers
for educational inspection; reuse requires written permission.
