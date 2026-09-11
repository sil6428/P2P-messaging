# Contributing

Small pull requests are preferred. A security-sensitive change should include a
failure-case test and update the threat model when it changes a trust boundary.
Do not commit identity files, passwords, private keys, real conversations, or
production endpoints.

## Good next pieces for a second contributor

These are intentionally left out of the first peer-to-peer milestone so another
contributor can own meaningful work rather than polishing finished code:

1. **Contact book and verification state** — persist imported peer cards, record
   whether a fingerprint was verified, and refuse unverified contacts by default.
2. **Conversation interface** — build a small local desktop or terminal UI on top
   of `PeerServer` and `send_message`; keep private keys out of logs and crash reports.
3. **Encrypted local history** — design an at-rest storage boundary and tests for
   locked, corrupted, and wrong-password states before saving plaintext messages.
4. **Attachment integration** — connect the existing secure-file-transfer project,
   bind each file digest to a message, and quarantine integrity mismatches.
5. **Protocol robustness** — fuzz frame and envelope parsing, add per-peer rate
   limits, and exercise slow clients, disconnects, and full-disk failures.

NAT traversal, relay fallback, groups, multi-device identity, and a standard
forward-secret protocol are later design projects. They should not be slipped
into a cosmetic pull request.

## Definition of done

- new behavior and meaningful failure cases are tested;
- `ruff check src tests` and `pytest -q` pass;
- user-visible claims match the implemented evidence;
- no secret or generated runtime file appears in the diff;
- the pull request explains any new trust assumption.
