<div align="center">
  <h1>P2P Messaging</h1>
  <p><strong>Verified peers, authenticated encryption, and replay-resistant direct messaging.</strong></p>
  <p>A collaborative Python security project for sending messages directly between two explicitly trusted peers without a central message server.</p>

  <p>
    <a href="https://github.com/sil6428/P2P-messaging/actions/workflows/quality.yml"><img alt="Quality checks" src="https://github.com/sil6428/P2P-messaging/actions/workflows/quality.yml/badge.svg"></a>
    <img alt="Python 3.11 or newer" src="https://img.shields.io/badge/Python-3.11%2B-3776ab?logo=python&amp;logoColor=white">
    <img alt="Educational work in progress" src="https://img.shields.io/badge/Status-Educational_WIP-f59e0b">
  </p>

  <p>
    <a href="docs/PROTOCOL.md">Protocol</a> ·
    <a href="docs/THREAT_MODEL.md">Threat model</a> ·
    <a href="SECURITY.md">Security policy</a> ·
    <a href="CHANGELOG.md">Changelog</a>
  </p>
</div>

> [!WARNING]
> This is an unaudited learning system. It demonstrates secure-communications concepts, but it is not ready for sensitive or production use.

Built collaboratively by Affan Shaikh and Ghayas Sher.

## What works

- **Protected device identities.** Ed25519 and X25519 private keys are encrypted with a user password.
- **Explicit peer trust.** Public peer cards include self-signatures and human-checkable fingerprints; sending stays blocked until a fingerprint is verified out of band.
- **Authenticated messages.** ChaCha20-Poly1305 encrypts message content and routing metadata, while Ed25519 signs each envelope.
- **Verified delivery.** The sender accepts delivery only after decrypting the recipient's matching acknowledgement.
- **Persistent replay rejection.** Claimed message IDs survive restarts and repeated envelopes are rejected.
- **Encrypted local history.** Conversation history uses a separate password and authenticated metadata.
- **Bounded transport.** The protocol enforces 64 KiB frames, 4 KiB plaintext messages, recipient checks, expiry windows, timeouts, and per-peer rate limits.
- **Local browser workspace.** Setup, unlock, conversations, replies, search, drafts, pinned/muted/archived controls, listener state, and contact verification are available at `127.0.0.1`.
- **Attachment integrity references.** A filename, size, and SHA-256 digest can be authenticated inside a message and checked after the file moves through another channel.

## How it works

```text
Password-protected device identity
              ↓
Verified peer card + out-of-band fingerprint check
              ↓
Signed and ChaCha20-Poly1305-encrypted envelope
              ↓ direct bounded TCP connection
Recipient, timestamp, signature, encryption, and replay checks
              ↓
Encrypted acknowledgement + encrypted local history
```

There is no hosted account or central message service. One peer listens on a TCP endpoint and the other connects directly using the endpoint and public keys in a shared peer card.

## Open the local app

Requires Python 3.11 or newer.

```bash
git clone https://github.com/sil6428/P2P-messaging.git
cd P2P-messaging
python -m venv .venv
```

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
secure-messaging serve
```

The app opens at `http://127.0.0.1:8000`. On first launch it creates a password-protected identity, a public peer card, and a separate encrypted history store.

To exchange messages:

1. Exchange public peer-card JSON with the other person.
2. Compare fingerprints through a different trusted channel.
3. Mark the matching fingerprint verified.
4. Keep both peer listeners reachable and send.

<details>
<summary><strong>Try two peers from the command line</strong></summary>

Create separate local identities:

```bash
secure-messaging identity init --name Alice \
  --identity alice.identity.json --card alice.peer.json \
  --endpoint 127.0.0.1:8765

secure-messaging identity init --name Bob \
  --identity bob.identity.json --card bob.peer.json \
  --endpoint 127.0.0.1:8766
```

Start Bob's listener:

```bash
secure-messaging listen --identity bob.identity.json \
  --trust alice.peer.json --database bob-state.db \
  --host 127.0.0.1 --port 8766
```

Send from Alice:

```bash
secure-messaging send --identity alice.identity.json \
  --peer bob.peer.json --message "hello Bob"
```

</details>

## Verified evidence

### Automated tests

```bash
ruff check src tests
pytest -q
```

The current **75-test** suite covers authentication and CSRF boundaries, identity protection, contact verification, signatures, authenticated encryption, expiry and recipient checks, acknowledgements, persistent replay rejection, encrypted history, attachment references, rate limits, bounded frames, malformed inputs, and end-to-end loopback delivery.

### 5,000-message replay benchmark

```bash
python scripts/run_message_benchmark.py --messages 5000 --workers 32
```

The verified loopback run:

- accepted **5,000** unique messages;
- validated **5,000** encrypted acknowledgements;
- rejected **5,000** replay attempts; and
- persisted exactly **5,000** unique message IDs.

Every accepted delivery crossed the real TCP transport and passed peer-card verification, Ed25519 signature validation, X25519 key agreement, ChaCha20-Poly1305 decryption, and persistent message-ID claiming. Review the machine-readable evidence in [`results/message-replay-benchmark.json`](results/message-replay-benchmark.json).

## Security boundaries

The project intentionally does **not** claim:

- forward secrecy or automatic key rotation;
- NAT traversal or relay infrastructure;
- multi-device identity synchronization;
- automatic attachment transfer;
- independent security review; or
- production availability guarantees.

A self-signed peer card proves that the card was not edited after signing; it does not prove who owns the key. Users still need an out-of-band fingerprint comparison. Read the [threat model](docs/THREAT_MODEL.md) and [protocol notes](docs/PROTOCOL.md) before experimenting with the system.

## Development

### Repository map

| Path | Purpose |
| --- | --- |
| `src/secure_messaging/identity.py` | Device identities, peer cards, key protection, and fingerprints |
| `src/secure_messaging/protocol.py` | Signed and encrypted message envelopes |
| `src/secure_messaging/transport.py` | Bounded TCP framing, listeners, delivery, and acknowledgements |
| `src/secure_messaging/contacts.py` | Imported contacts and out-of-band verification state |
| `src/secure_messaging/history.py` | Password-protected local conversation history |
| `src/secure_messaging/attachments.py` | Attachment-digest references and verification |
| `src/secure_messaging/web_service.py` | Local browser workspace and API boundary |
| `tests/` | Protocol, transport, web, storage, fuzz, and CLI coverage |
| `scripts/` | Reproducible benchmark tooling |

The machine-readable `/status` endpoint reports implemented features and known limits. [CONTRIBUTING.md](CONTRIBUTING.md) tracks the open recovery, audit, connection-control, and file-transfer work.

## Status and licence

P2P Messaging is a collaborative educational work in progress. Attachment bytes still move through a separate channel; this repository authenticates only their references. Integration with the separate Secure File Transfer project remains planned.

All rights reserved. The repository is public for portfolio and educational review; reuse requires written permission. See [`LICENSE`](LICENSE).
