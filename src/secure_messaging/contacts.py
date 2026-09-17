from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from secure_messaging.identity import PeerCard

SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    signing_key BLOB PRIMARY KEY,
    display_name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    version INTEGER NOT NULL,
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TEXT
);
"""

MIN_FINGERPRINT_PREFIX_LENGTH = 8


class ContactError(ValueError):
    """Raised when a contact-book operation cannot be completed safely."""


def _row_to_card(
    signing_key: bytes,
    display_name: str,
    endpoint: str,
    encryption_key: bytes,
    signature: bytes,
    version: int,
) -> PeerCard:
    return PeerCard(
        display_name=display_name,
        endpoint=endpoint,
        signing_key=signing_key,
        encryption_key=encryption_key,
        signature=signature,
        version=version,
    )


class ContactBook:
    """Persists imported peer cards and whether each fingerprint was verified out-of-band.

    Only ``verified_contacts`` should feed a trust list: importing a card proves it was
    not edited after signing, not that the signer is who they claim to be.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def add(self, card: PeerCard) -> None:
        """Import or refresh a peer card. Re-importing a known key never clears its verified state."""
        card.verify()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO contacts(signing_key, display_name, endpoint, encryption_key, signature, version)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(signing_key) DO UPDATE SET
                    display_name = excluded.display_name,
                    endpoint = excluded.endpoint,
                    encryption_key = excluded.encryption_key,
                    signature = excluded.signature,
                    version = excluded.version
                """,
                (
                    card.signing_key,
                    card.display_name,
                    card.endpoint,
                    card.encryption_key,
                    card.signature,
                    card.version,
                ),
            )

    def mark_verified(self, signing_key: bytes) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE contacts SET verified_at = ? WHERE signing_key = ?",
                (datetime.now(UTC).isoformat(timespec="seconds"), signing_key),
            )
            if cursor.rowcount == 0:
                raise ContactError("Unknown contact; import the peer card before verifying it.")

    def is_verified(self, signing_key: bytes) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT verified_at FROM contacts WHERE signing_key = ?", (signing_key,)
            ).fetchone()
        return row is not None and row[0] is not None

    def get(self, signing_key: bytes) -> PeerCard | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT signing_key, display_name, endpoint, encryption_key, signature, version "
                "FROM contacts WHERE signing_key = ?",
                (signing_key,),
            ).fetchone()
        return None if row is None else _row_to_card(*row)

    def find_by_fingerprint_prefix(self, prefix: str) -> PeerCard:
        """Look up a contact by a human-typed prefix of its fingerprint (case- and space-insensitive)."""
        clean_prefix = prefix.replace(" ", "").upper()
        if len(clean_prefix) < MIN_FINGERPRINT_PREFIX_LENGTH or any(
            character not in "0123456789ABCDEF" for character in clean_prefix
        ):
            raise ContactError(
                f"Fingerprint prefix must contain at least {MIN_FINGERPRINT_PREFIX_LENGTH} hex characters."
            )
        matches = [card for card, _ in self.all_contacts() if card.fingerprint.replace(" ", "").startswith(clean_prefix)]
        if not matches:
            raise ContactError("No contact matches that fingerprint.")
        if len(matches) > 1:
            raise ContactError("Fingerprint prefix matches more than one contact; use more characters.")
        return matches[0]

    def verified_contacts(self) -> list[PeerCard]:
        """Contacts safe to trust automatically: unverified contacts are excluded by default."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT signing_key, display_name, endpoint, encryption_key, signature, version "
                "FROM contacts WHERE verified_at IS NOT NULL"
            ).fetchall()
        return [_row_to_card(*row) for row in rows]

    def all_contacts(self) -> list[tuple[PeerCard, bool]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT signing_key, display_name, endpoint, encryption_key, signature, version, verified_at "
                "FROM contacts ORDER BY imported_at"
            ).fetchall()
        return [(_row_to_card(*row[:6]), row[6] is not None) for row in rows]
