# Initial Threat Model

Status: foundation milestone. Revisit this document with every feature that
changes a trust boundary.

## Assets

- account credentials and sessions;
- message and attachment contents;
- conversation membership;
- attachment integrity metadata;
- audit records and service availability.

## Trust boundaries

- browser or desktop client to messaging service;
- messaging service to its database;
- messaging service to the future attachment service;
- authenticated user to another user's conversations;
- service operator to stored plaintext.

## Initial attacker capabilities

The design assumes an attacker may control a normal account, submit malformed
input, guess identifiers, interrupt connections, replay client requests, or
modify files in storage after upload. A passive network observer is expected to
be limited by correctly configured TLS.

## Controls planned with their features

- memory-hard password hashing, generic failures, session rotation, and login
  throttling before accounts are enabled;
- membership checks on every conversation operation;
- bounded message, frame, and attachment sizes;
- per-file SHA-256 manifests, pre-download re-hashing, post-download checking,
  and quarantine for integrity mismatches;
- structured audit events that exclude passwords and message bodies;
- automated negative tests for authorization and malformed inputs.

## Explicit non-goals for the current version

- production deployment;
- anonymous communication;
- protection from a malicious or compromised service operator;
- end-to-end encryption;
- malware detection or content-safety scanning;
- guaranteed delivery under unbounded resource exhaustion.

## Security claims currently allowed

The current repository may claim to have a documented threat model, a
constraint-driven data schema, and automated foundation tests. It must not
claim secure messaging, end-to-end encryption, production readiness, or an
external audit until those claims are supported by implemented evidence.

