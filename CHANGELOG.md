# Changelog

## 0.1.0 - 2026-09-10

- Added password-protected device identities and signed peer cards.
- Added authenticated direct-message encryption and encrypted acknowledgements.
- Added a bounded TCP peer transport with persistent replay rejection.
- Added a two-terminal demo, protocol documentation, and contributor handoffs.

## Unreleased

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
  quarantines integrity mismatches.
- Added per-peer sliding-window rate limiting and a per-connection read
  timeout to the peer transport.
- Added fuzz-style tests for envelope and frame parsing.
- Updated the roadmap, threat model, and protocol docs for the above.
