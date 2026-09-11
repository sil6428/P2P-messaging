# Threat Model

Status: peer messaging milestone. Revisit this document with every feature that
changes a trust boundary.

## Assets

- device identity private keys and trusted peer cards;
- message plaintext, ciphertext, and delivery acknowledgements;
- peer endpoints and communication metadata;
- replay records, future attachments, and service availability.

## Trust boundaries

- identity file and the local operating-system account;
- trusted peer card and the out-of-band fingerprint comparison;
- one peer's TCP socket to the other peer's listener;
- encrypted network envelope to delivered plaintext;
- the future attachment service and local file storage.

## Initial attacker capabilities

The design assumes an attacker may observe, interrupt, reorder, replay, or alter
network traffic; connect without a trusted identity; submit malformed or
oversized frames; or modify a peer card in transit. A local attacker that can
read a device's private identity file is outside the current protection model.

## Controls planned with their features

- fingerprint comparison before a peer card is trusted;
- signed peer cards and signed, authenticated-encryption envelopes;
- recipient checks plus bounded message, frame, and future attachment sizes;
- persistent message identifiers to reject replays after restart;
- per-file SHA-256 manifests, pre-download re-hashing, post-download checking,
  and quarantine for integrity mismatches;
- structured local events that exclude private keys and message bodies;
- automated negative tests for authorization and malformed inputs.

## Explicit non-goals for the current version

- production deployment;
- anonymous communication or traffic-analysis resistance;
- forward secrecy, post-compromise security, or automatic key rotation;
- protection after an endpoint or identity file is compromised;
- malware detection or content-safety scanning;
- guaranteed delivery under unbounded resource exhaustion.

## Security claims currently allowed

The current repository may claim encrypted, authenticated direct messages
between peers whose fingerprints were verified separately. It must not claim a
standard audited protocol, forward secrecy, compromise recovery, anonymity, or
production readiness.
