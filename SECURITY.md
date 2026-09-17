# Security Policy

## Project status

This project is under active development and must not be used for confidential
or sensitive communication. It implements authenticated, encrypted direct
messages between explicitly trusted peer cards, but its custom protocol has
not been independently audited and does not provide forward secrecy.

The contact book requires an out-of-band fingerprint comparison before a card
joins the automatic trust list. Local message history is encrypted with a
separate password. These controls reduce specific risks; they do not make the
project production-ready.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner.
Do not include working credentials, private messages, or other sensitive data
in a public issue.

Public issues are appropriate for non-sensitive bugs, documentation errors,
and feature proposals.

