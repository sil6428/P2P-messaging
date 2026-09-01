# Roadmap

This roadmap exists to make the development story inspectable. Each milestone
must include tests and update the threat model when it changes the attack
surface.

## Milestone 1: identity and sessions

- Normalize and uniquely store email addresses.
- Hash passwords with a memory-hard password function and unique salts.
- Add generic authentication failures to reduce account enumeration.
- Rotate opaque sessions after login and revoke them at logout.
- Rate-limit authentication attempts.

## Milestone 2: direct messages

- Require membership before reading or writing a conversation.
- Give messages server-generated identifiers and ordering timestamps.
- Validate message size and reject unsupported content.
- Test horizontal-authorization failures between users.

## Milestone 3: delivery

- Deliver messages over authenticated WebSocket connections.
- Reconnect without duplicating acknowledged messages.
- Queue messages for offline recipients.
- Bound queues and apply backpressure.

## Milestone 4: verified attachments

- Reuse the secure-transfer protocol as a separate attachment service.
- Bind an attachment record to sender, conversation, size, and SHA-256 digest.
- Resume interrupted transfers from verified offsets.
- Re-hash before download and after receipt.

## Milestone 5: integrity states

- Show `verified`, `unverified`, and `integrity mismatch` states.
- Quarantine mismatches instead of exposing them as completed downloads.
- Record security-relevant attachment events without logging message contents.
- State clearly that integrity verification is not malware detection.

## Milestone 6: hardening

- Add message and transfer rate limits.
- Exercise malformed frames, disconnects, replay attempts, and storage failure.
- Add end-to-end integration tests and a reproducible demo environment.
- Document deployment boundaries and incident-recovery steps.

End-to-end encryption is a separate future research milestone. It will use an
established protocol and maintained cryptographic implementation if attempted;
the project will not invent a custom encryption scheme.

