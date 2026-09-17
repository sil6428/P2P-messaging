# Peer Protocol v1

Status: educational milestone. The protocol is intentionally small enough to
review, but it has not been independently audited and is not ready for
sensitive conversations.

## Trust setup

Each device owns two long-lived key pairs:

- an Ed25519 key signs peer cards and message envelopes;
- an X25519 key establishes a shared secret with a peer.

A peer card contains a display name, both public keys, and a reachable
`host:port` endpoint. The card is self-signed so accidental edits are detected.
Users still have to compare the displayed signing-key fingerprint through a
separate trusted channel. A valid self-signature does not prove who controls a
key.

## Message protection

For each direct message, the sender:

1. derives a directional key from the static X25519 shared secret with HKDF-SHA256;
2. creates a fresh 96-bit random nonce;
3. encrypts the UTF-8 message with ChaCha20-Poly1305;
4. binds the protocol version, message identifier, sender, recipient, timestamp,
   and nonce as authenticated additional data; and
5. signs the authenticated header and ciphertext with Ed25519.

The receiver checks the trusted peer card, envelope signature, intended
recipient, timestamp format, message size, AEAD tag, and persistent replay
record before delivering the plaintext. Acknowledgements use the same encrypted
and signed envelope format and reference the accepted message identifier.

Frames are four-byte big-endian length-prefixed JSON documents. Receivers reject
frames larger than 64 KiB before allocating the payload.

## Security properties and limits

Implemented in this milestone:

- confidentiality and integrity between two peers that already trust each
  other's fingerprint;
- sender authentication against the stored peer card;
- recipient binding, bounded frames and messages, and persistent replay
  detection;
- encrypted acknowledgements so the sender can verify who accepted a message;
- an optional attachment reference (filename, size, SHA-256) bound into the
  same signed, encrypted envelope, so a file transferred out-of-band (by the
  separate secure-file-transfer project) can be integrity-checked on arrival;
- post-authentication per-peer rate limiting and a per-connection read timeout
  at the listener;
- an encrypted local message history, locked by its own password, with row
  identity metadata bound through authenticated additional data;
- a contact book that tracks whether each imported peer card's fingerprint was
  verified out-of-band, and excludes unverified contacts from the trust list
  used by `listen` unless explicitly overridden.

Not implemented:

- forward secrecy or post-compromise security;
- automatic key changes, multi-device identity, groups, or account recovery;
- NAT traversal, relays, or anonymous metadata;
- the file-transfer bytes themselves (only the digest reference travels here);
- automatic file quarantine or a global unauthenticated-connection cap;
- protection when either endpoint, its identity file, or its trusted-contact
  directory is compromised.

The project uses maintained primitives from `cryptography`; it does not claim to
implement a standard secure-messaging protocol such as Signal's Double Ratchet.
That should be a later, separately reviewed milestone.
