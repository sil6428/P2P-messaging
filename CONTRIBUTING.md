# Contributing

Small pull requests are preferred. A security-sensitive change should include a
failure-case test and update the threat model when it changes a trust boundary.
Do not commit identity files, passwords, private keys, real conversations, or
production endpoints.

## Good next pieces for a second contributor

Milestones 4-6 (contact book and verification state, the `chat` interface and
encrypted local history, and attachment digest binding with quarantine) are
now implemented; see [ROADMAP.md](docs/ROADMAP.md). What's still open:

1. **Full attachment-transfer integration** — this repository only binds and
   verifies a SHA-256 digest reference inside a message; wiring an actual file
   transfer to the separate secure-file-transfer project, including a shared
   download/quarantine directory convention, is still unclaimed.
2. **Failure recovery** — exercise disconnects mid-exchange and full-disk
   conditions for the peer transport, history store, and contact book, and
   decide on retry/backoff behavior.
3. **Structured local audit events** — log security-relevant actions (contact
   imports, verification, rejected peers) without ever including private keys
   or message bodies.
4. **Packaging** — a distributable build (e.g. a signed wheel or platform
   installer) instead of `pip install -e`.

NAT traversal, relay fallback, groups, multi-device identity, and a standard
forward-secret protocol are later design projects. They should not be slipped
into a cosmetic pull request.

## Definition of done

- new behavior and meaningful failure cases are tested;
- `ruff check src tests` and `pytest -q` pass;
- user-visible claims match the implemented evidence;
- no secret or generated runtime file appears in the diff;
- the pull request explains any new trust assumption.
