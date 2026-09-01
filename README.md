# Secure Messaging Platform

> **Work in progress.** The repository is being built in small, reviewable
> milestones. It is not ready for private or sensitive conversations.

A security-focused messaging service that will combine authenticated direct
messages with verified file transfer. The final integration will show the
receiver whether an attachment arrived intact, quarantine content when its
digest does not match, and keep an auditable record of security-relevant
events.

The progression is deliberate:

1. [File Integrity Monitor](https://github.com/sil6428/file-integrity-monitor)
   established hashing, baselines, and change detection.
2. [Secure File Transfer](https://github.com/sil6428/secure-file-transfer)
   applies authenticated TLS, resumable transfer, recipient isolation, and
   end-to-end file-integrity verification.
3. This project will combine those ideas with accounts, conversations,
   real-time delivery, attachment status, and operational safeguards.

## Current milestone: foundation

The first milestone contains:

- a FastAPI application shell with an explicit development-status endpoint;
- a versioned SQLite schema for users, sessions, conversations, messages,
  attachments, and audit events;
- foreign keys and constraints that encode the first data-boundary decisions;
- automated tests for application status, schema creation, and idempotent
  migrations;
- an initial threat model and a milestone roadmap.

There is intentionally no registration, login, messaging, or file upload yet.
Those features will be added only when their security controls and tests can be
added in the same milestone.

## Run the foundation

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

python -m pip install -e ".[dev]"
secure-messaging serve
```

Open `http://127.0.0.1:8000/status`. The response deliberately reports
`development`, so the current state cannot be mistaken for a completed secure
product.

Run the checks:

```bash
ruff check src tests
pytest -q
```

## Milestones

| Milestone | Deliverable | Status |
|---|---|---|
| 0 | Application shell, schema, threat model, tests | Complete |
| 1 | Account creation, password hashing, session controls | Planned |
| 2 | Authenticated direct messages and conversation access rules | Planned |
| 3 | Real-time delivery, reconnect handling, offline queue | Planned |
| 4 | Verified attachments using the secure-transfer pipeline | Planned |
| 5 | Integrity warning states, quarantine, and audit views | Planned |
| 6 | Rate limits, abuse cases, integration tests, deployment guide | Planned |

The order can change when testing exposes a better dependency order. A commit
should represent a real feature, test, design decision, or documented finding;
the project will not use empty commits to simulate activity.

## Security language

Until a later milestone says otherwise, “secure” means the project is being
designed with explicit security controls and tested failure cases. It does not
mean end-to-end encrypted, independently audited, or production-ready. TLS
protects network traffic from passive observers but does not hide plaintext
from the service operator. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

All rights reserved. The code may be shared with authorized portfolio reviewers
for educational inspection; reuse requires written permission.
