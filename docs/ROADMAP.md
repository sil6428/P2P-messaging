# Roadmap

Each milestone must include failure-case tests and update the threat model when
it changes a trust boundary.

| Milestone | Deliverable | Status |
|---|---|---|
| 0 | Application shell, schema, threat model, checks | Complete |
| 1 | Signed device identity and password-protected key file | Complete |
| 2 | Encrypted direct-message envelope and authenticated acknowledgement | Complete |
| 3 | Bounded TCP peer transport and persistent replay protection | Complete |
| 4 | Contact book with explicit fingerprint-verification state | Available |
| 5 | Local conversation UI and encrypted message history | Available |
| 6 | Verified attachment transfer and integrity warning states | Available |
| 7 | Rate limits, parser fuzzing, failure recovery, packaging | Planned |

“Available” milestones are intentionally scoped for another contributor. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for acceptance criteria.

NAT traversal and relay fallback follow only after the local and LAN security
boundaries are stable. Forward secrecy must use a maintained standard protocol
implementation; this project will not invent a Double Ratchet substitute.
