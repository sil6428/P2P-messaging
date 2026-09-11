# Secure Messaging Platform

> **Educational work in progress.** This project now supports a small encrypted
> peer-to-peer demo. It is not independently audited or ready for sensitive use.

A Python learning project for direct messages between two explicitly trusted
peers. There is no central message server: one peer listens on a TCP endpoint and
the other connects directly using a shared public peer card.

## What works

- password-protected Ed25519 and X25519 device identities;
- self-signed public peer cards with human-checkable fingerprints;
- ChaCha20-Poly1305 message encryption with authenticated routing metadata;
- Ed25519 envelope signatures and encrypted delivery acknowledgements;
- 64 KiB frame limits, 4 KiB plaintext limits, recipient checks, and persistent
  replay rejection;
- tests for tampering, expired messages, wrong recipients, unknown peers,
  oversized frames, replay attempts, and end-to-end delivery.

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

## Collaborating

[CONTRIBUTING.md](CONTRIBUTING.md) lists substantial next pieces deliberately
left for another contributor: contact verification state, a conversation UI,
encrypted history, attachment integration, and protocol robustness. The current
code provides interfaces and tests those features can build on without pretending
the project is finished.

## License

All rights reserved. The code may be shared with authorized portfolio reviewers
for educational inspection; reuse requires written permission.
