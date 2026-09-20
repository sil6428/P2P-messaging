# Changelog

## 0.1.0 - 2026-09-10

- Added password-protected device identities and signed peer cards.
- Added authenticated direct-message encryption and encrypted acknowledgements.
- Added a bounded TCP peer transport with persistent replay rejection.
- Added a two-terminal demo, protocol documentation, and contributor handoffs.

## Unreleased

### Local messaging interface

- Added first-time device setup and local unlock without introducing a hosted
  account service or storing unlock passwords in the application database.
- Added separate verified-contact conversations, authenticated message replies,
  encrypted-history search, local drafts, and pinned, muted, and archived controls.
- Added live peer-listener status, authenticated delivery-state labels, peer
  card import/export, and fingerprint verification inside the interface.
- Added browser-side SHA-256 file binding so file bytes remain local while the
  signed attachment reference travels with the encrypted message.
- Added HTTP-only same-site sessions and CSRF validation for every state-changing
  authenticated endpoint.
- Added browser-flow tests and expanded the automated suite to 75 passing tests.

### Foundation

- Added the FastAPI application shell and development-status endpoint.
- Added the versioned SQLite schema and idempotent initialization.
- Added schema and endpoint tests.
- Documented the initial threat model and milestone plan.

### Milestones 4-7

- Added a local contact book that tracks fingerprint-verification state and
  excludes unverified contacts from the automatic trust list.
- Added an interactive `chat` command alongside the one-shot `send`/`listen`
  commands.
- Added an encrypted local message history, locked by its own password and
  independent of the device identity password.
- Added attachment digest references (filename, size, SHA-256) bound into the
  signed, encrypted envelope, plus a `verify-attachment` command that
  reports integrity mismatches and unreadable files.
- Added per-peer sliding-window rate limiting and a per-connection read
  timeout to the peer transport.
- Added fuzz-style tests for envelope and frame parsing.
- Required at least eight hexadecimal fingerprint characters when selecting a
  contact, preventing empty or ambiguous verification input.
- Bound message IDs, peer keys, and direction into encrypted-history
  authentication; history passwords now require at least 12 characters.
- Corrected sent history to retain the original message rather than the
  acknowledgement, and associated received history with the authenticated
  sender key rather than a display name.
- Moved rate-limit accounting after sender authentication so forged envelopes
  cannot consume a trusted peer's allowance.
- Bound the signed attachment filename into verification alongside its size
  and SHA-256 digest.
- Expanded the automated suite to 72 passing tests before the browser interface milestone.
- Updated the roadmap, threat model, and protocol docs for the above.
