# Roadmap

Each milestone must include failure-case tests and update the threat model when
it changes a trust boundary.

| Milestone | Deliverable | Status |
|---|---|---|
| 0 | Application shell, schema, threat model, checks | Complete |
| 1 | Signed device identity and password-protected key file | Complete |
| 2 | Encrypted direct-message envelope and authenticated acknowledgement | Complete |
| 3 | Bounded TCP peer transport and persistent replay protection | Complete |
| 4 | Contact book with explicit fingerprint-verification state | Complete |
| 5 | Local conversation UI, device unlock, and encrypted message history | Complete |
| 6 | Attachment-reference binding and integrity warning states | Complete |
| 7 | Transport hardening, failure recovery, audit events, packaging | In progress |
| 8 | Integrated secure file transfer, progress, resume, and quarantine | Planned |
| 9 | History search and contact-safety usability | Complete |
| 10 | Encrypted history export with explicit redaction controls | Planned |
| 11 | NAT traversal or relay fallback with explicit metadata tradeoffs | Planned |
| 12 | Maintained standard forward-secret protocol implementation | Research |

Milestone 7 currently covers authenticated-peer rate limiting, slow-client read
timeouts, and envelope/frame parser fuzz tests. Global connection controls,
failure recovery (full-disk and interrupted writes), structured audit events,
and packaging remain open. See [CONTRIBUTING.md](../CONTRIBUTING.md) for
acceptance criteria.

NAT traversal and relay fallback follow only after the local and LAN security
boundaries are stable. Forward secrecy must use a maintained, reviewed
implementation of a standard protocol; this project will not invent a Double
Ratchet substitute.
