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
| 5 | Local conversation UI and encrypted message history | Complete |
| 6 | Verified attachment transfer and integrity warning states | Complete |
| 7 | Rate limits, parser fuzzing, failure recovery, packaging | In progress |

Milestone 7 currently covers per-peer rate limiting, slow-client read timeouts,
and envelope/frame parser fuzz tests; failure recovery (full-disk, mid-transfer
disconnects) and packaging are still open. See [CONTRIBUTING.md](../CONTRIBUTING.md)
for acceptance criteria on what remains.

NAT traversal and relay fallback follow only after the local and LAN security
boundaries are stable. Forward secrecy must use a maintained standard protocol
implementation; this project will not invent a Double Ratchet substitute.
