# Threat Model

Status: peer messaging milestone. Revisit this document with every feature that
changes a trust boundary.

## Assets

- device identity private keys and trusted peer cards;
- message plaintext, ciphertext, and delivery acknowledgements;
- peer endpoints and communication metadata;
- replay records, attachment digest references, encrypted local history, and
  service availability.

## Trust boundaries

- identity file and the local operating-system account;
- trusted peer card and the out-of-band fingerprint comparison;
- one peer's TCP socket to the other peer's listener;
- encrypted network envelope to delivered plaintext;
- an attachment's digest reference (sent over this protocol) versus the file
  bytes themselves (moved by the separate secure-file-transfer project);
- the encrypted local history store and its own, separate password.

## Initial attacker capabilities

The design assumes an attacker may observe, interrupt, reorder, replay, or alter
network traffic; connect without a trusted identity; submit malformed or
oversized frames; or modify a peer card in transit. A local attacker that can
read a device's private identity file is outside the current protection model.

## Controls implemented

- fingerprint comparison before a peer card is trusted; the contact book stores
  imported cards as unverified until that comparison happens and excludes them
  from the automatic trust list until then;
- signed peer cards and signed, authenticated-encryption envelopes;
- recipient checks plus bounded message and frame sizes;
- persistent message identifiers to reject replays after restart;
- per-peer sliding-window rate limiting and a read timeout on each connection,
  so one peer (trusted or not) cannot exhaust the listener with slow or
  excessive traffic;
- attachment references carry only a filename, size, and SHA-256 digest inside
  the encrypted, signed message; the recipient re-hashes the downloaded file
  and must quarantine any digest or size mismatch before trusting it;
- an independently encrypted local message history, locked by its own
  password rather than the device identity password, so a copied history file
  reveals nothing without it;
- automated negative and fuzz tests for authorization, malformed frames, and
  malformed envelopes.

## Controls still planned

- structured local events that exclude private keys and message bodies;
- failure recovery under full-disk and mid-transfer disconnect conditions.

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
