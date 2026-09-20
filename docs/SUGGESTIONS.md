# Suggestions and comparison notes

This is a launch pad for the next contributor, not a promise that every item
will ship. Relay is an educational direct-messaging project. It should stay
small enough that every security claim can be explained and tested.

The comparison below samples maintained projects and published protocols with
different goals. It is not a claim that every messaging repository on GitHub
was reviewed, and it is not permission to copy code without checking its
license.

## Best next contributions

### 1. Bound unauthenticated connection pressure

**Why first:** the listener limits frames, read time, and authenticated peers,
but it still accepts an unbounded number of simultaneous connections. A remote
client can hold many sockets until their timeouts expire and consume memory and
tasks.

**Deliverable**

- add a global concurrent-connection cap around the pre-authentication path;
- immediately reject or close excess connections with the same generic error;
- expose only an aggregate rejected-connection count, never remote message
  contents or keys;
- test a burst above the cap, a slot becoming available again, and shutdown
  while connections are open.

### 2. Add structured local security events

Record contact imports, verification changes, listener start/stop, replay
rejections, rate-limit rejections, and malformed-frame rejections. Use event
names and safe counters. Do not store message bodies, passwords, private keys,
full public keys, session tokens, CSRF tokens, or raw peer-card JSON.

**Definition of done:** a test asserts both the events that are present and the
sensitive fields that are absent.

### 3. Build failure recovery before adding more UI

Exercise full-disk errors, interrupted history writes, an acknowledgement lost
after the recipient stores the message, and a disconnect during an attachment
transfer. Define whether each operation is retried, rolled back, marked
uncertain, or safely resumed. A retry must not display a duplicate message.

### 4. Integrate real file transfer

Relay currently sends only a signed filename, size, and SHA-256 reference. The
separate secure-file-transfer project should become the data path while Relay
provides the conversation and trust context.

Start with:

- explicit recipient acceptance before bytes move;
- encrypted chunks, a final authenticated manifest, progress, cancel, and
  resume;
- a size limit and a quarantine directory outside automatic-open locations;
- filename normalization that cannot escape the destination directory;
- a final digest comparison before the UI offers **Save as**;
- tests for reordered, missing, repeated, corrupted, and path-traversal chunks.

SimpleX uses a separate file-transfer protocol and passes file metadata through
chat messages, which is a useful separation of responsibilities:
<https://github.com/simplex-chat/simplex-chat/blob/stable/docs/protocol/simplex-chat.md>.

### 5. Make peer-card exchange easier without weakening verification

Add QR import/export and a short comparison code derived from both identity
public keys. Keep the existing out-of-band comparison and stop sending after a
verified identity key changes until the user explicitly accepts it. Signal's
session-management specification similarly treats an identity-key change as a
reason to pause and re-authenticate:
<https://signal.org/docs/specifications/sesame/>.

A later experiment could use a reviewed PAKE-based pairing flow rather than a
home-grown short-code exchange. Magic Wormhole is a useful reference for
short-code-assisted encrypted channel establishment:
<https://github.com/magic-wormhole/magic-wormhole>.

## Architecture work that needs a design review first

### Forward secrecy and recovery after key compromise

Relay derives message keys from long-lived X25519 keys. If a device identity is
stolen, recorded ciphertext for that identity can be decrypted. Random nonces
prevent ciphertext reuse, but they do not provide forward secrecy or recovery
after compromise.

Do not write a custom ratchet. Evaluate a maintained implementation of a
reviewed protocol, prototype migration separately, and version the wire format.
Signal's Double Ratchet derives new keys as messages are exchanged, providing
forward security and break-in recovery:
<https://signal.org/docs/specifications/doubleratchet/>. The Noise framework is
another reviewed family of authenticated handshakes with forward-secrecy
patterns: <https://noiseprotocol.org/>.

Acceptance criteria for any migration must include lost/out-of-order messages,
state rollback, skipped-key storage bounds, identity-key changes, old-client
rejection, and a written downgrade analysis.

### Offline delivery, relays, and NAT traversal

Direct TCP keeps the demo understandable, but peers often cannot accept inbound
connections through NAT, firewalls, or sleep states. A relay can queue encrypted
messages without receiving plaintext, but it learns timing, address, and
connection metadata unless the design does more.

Useful references with different tradeoffs:

- Briar synchronizes directly over Bluetooth/Wi-Fi and uses Tor when the
  Internet is available: <https://github.com/briar/briar>.
- SimpleX uses temporary relay queues and deliberately avoids global user
  identifiers: <https://github.com/simplex-chat/simplex-chat>.
- Session stores offline messages on distributed service nodes and uses onion
  routing to obscure IP addresses:
  <https://github.com/session-foundation/session-desktop>.
- Tox uses a DHT for serverless discovery, but its own README warns that its
  security model is not formally audited:
  <https://github.com/TokTok/c-toxcore>.
- Jami demonstrates a separate communications daemon, distributed P2P calls,
  and richer call/file features:
  <https://github.com/savoirfairelinux/jami-daemon>.

Before choosing one, write down what the relay may learn, how long it retains
messages, how peers authenticate it, how abuse is controlled, and what happens
when both peers are offline.

### Groups and multiple devices

Do not stretch the one-to-one shared-secret design into group chat. For future
groups, investigate Messaging Layer Security (MLS), which standardizes
asynchronous group key establishment with forward secrecy and post-compromise
security: <https://www.rfc-editor.org/rfc/rfc9420>. OpenMLS is a maintained Rust
implementation: <https://github.com/openmls/openmls>.

For multiple devices, study Matrix cross-signing and device verification rather
than silently trusting every new device:
<https://github.com/matrix-org/matrix-spec/blob/main/content/client-server-api/modules/end_to_end_encryption.md>.

## Feature comparison

| Capability | Relay now | Mature reference lesson | Sensible Relay direction |
|---|---|---|---|
| Direct encrypted text | Implemented and tested | Common baseline | Keep the small, testable envelope |
| Forward secrecy | Not implemented | Signal/SimpleX rotate session keys | Research a maintained protocol; do not invent one |
| Offline delivery | Both peers must be online | Signal Sesame and SimpleX use asynchronous queues | Design an optional encrypted relay with explicit metadata costs |
| Peer discovery | Signed peer-card exchange | Tox/Jami use distributed discovery | Keep manual cards first; add QR before DHT complexity |
| Address privacy | Peers see each other's address | Briar/Session route through Tor/onion paths | Document the limitation before considering privacy transport |
| Attachments | Authenticated digest reference only | SimpleX separates chat metadata from encrypted file transport | Integrate the existing transfer project with quarantine and resume |
| Groups | Not implemented | MLS addresses asynchronous group keying | Treat as a separate protocol milestone |
| Multiple devices | One identity file/device | Matrix uses device verification and cross-signing | Require explicit device enrollment and revocation |
| Local database | Message bodies encrypted; contact metadata visible | Session uses an encrypted local database | Document visible metadata, then evaluate whole-database encryption |
| Calls | Not implemented | Jami separates UI from a capable communications daemon | Defer until messaging and transport are stable |

## Red-team checklist for each release

- Can thousands of silent sockets exhaust the listener before authentication?
- Can an oversized length, malformed JSON, invalid base64, or deeply nested
  object cause unbounded memory/CPU use or crash the process?
- Can replay storage or local history grow until the disk is full?
- Does a changed identity or encryption key require a visible security decision?
- Can a retry after a lost acknowledgement create a duplicate conversation item?
- Can a crafted filename escape the quarantine/download directory?
- Does any log, status response, exception, or browser storage expose a password,
  private key, message body, token, or full contact card?
- If the long-term device key is stolen tomorrow, which recorded messages become
  readable? The answer must stay explicit until a ratcheting protocol ships.
- Can an older client be tricked into accepting a weaker protocol version?
- Do packaging and update instructions verify release provenance and integrity?

## Claims boundary

Until a reviewed forward-secret protocol and independent assessment exist,
describe Relay as an **educational encrypted P2P messaging project**. Do not
describe it as production secure, anonymous, audited, Signal-equivalent, or
post-compromise secure.
