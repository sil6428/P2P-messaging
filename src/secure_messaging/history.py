from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from secure_messaging.attachments import AttachmentReference
from secure_messaging.protocol import DecryptedMessage

HISTORY_VERSION = 2
PBKDF2_ITERATIONS = 600_000
MIN_HISTORY_PASSWORD_LENGTH = 12
CANARY_PLAINTEXT = b"secure-messaging-history-v1"
Direction = Literal["sent", "received"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS history_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL,
    canary_nonce BLOB NOT NULL,
    canary_ciphertext BLOB NOT NULL,
    version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS history_entries (
    message_id TEXT PRIMARY KEY,
    peer_signing_key BLOB NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('sent', 'received')),
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class HistoryError(ValueError):
    """Raised when the local encrypted history cannot be opened or written safely."""


class HistoryLocked(HistoryError):
    """Raised when the supplied history password does not unlock an existing store."""


class HistoryCorrupted(HistoryError):
    """Raised when a stored entry fails authenticated decryption."""


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    message_id: str
    peer_signing_key: bytes
    direction: Direction
    sender_name: str
    sent_at: datetime
    body: str
    attachment: AttachmentReference | None = None
    reply_to: str | None = None


def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS
    ).derive(password.encode("utf-8"))


def _entry_aad(message_id: str, peer_signing_key: bytes, direction: Direction) -> bytes:
    """Bind encrypted history to the row metadata used to identify it."""
    return json.dumps(
        {
            "direction": direction,
            "message_id": message_id,
            "peer_signing_key": peer_signing_key.hex(),
            "version": HISTORY_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class MessageHistory:
    """At-rest encrypted local message log.

    The store is locked by its own password, independent of the device identity
    password, so a compromised history file on disk reveals nothing without it.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._key: bytes | None = None

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def unlock(self, password: str) -> None:
        """Open the store for reading and writing, creating it on first use.

        The password is checked against a canary value independent of any stored
        message, so a wrong password (`HistoryLocked`) can never be mistaken for a
        corrupted entry (`HistoryCorrupted`) discovered later while reading.
        """
        if len(password) < MIN_HISTORY_PASSWORD_LENGTH:
            raise HistoryLocked(
                f"History password must be at least {MIN_HISTORY_PASSWORD_LENGTH} characters."
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            row = connection.execute(
                "SELECT salt, canary_nonce, canary_ciphertext, version "
                "FROM history_meta WHERE id = 1"
            ).fetchone()
            if row is None:
                salt = os.urandom(16)
                key = _derive_key(password, salt)
                canary_nonce = os.urandom(12)
                canary_ciphertext = ChaCha20Poly1305(key).encrypt(canary_nonce, CANARY_PLAINTEXT, None)
                connection.execute(
                    """
                    INSERT INTO history_meta(id, salt, canary_nonce, canary_ciphertext, version)
                    VALUES (1, ?, ?, ?, ?)
                    """,
                    (salt, canary_nonce, canary_ciphertext, HISTORY_VERSION),
                )
                self._key = key
                return
            salt, canary_nonce, canary_ciphertext, version = row

        if version != HISTORY_VERSION:
            raise HistoryLocked(
                "History format is unsupported; export it with the version that created it."
            )

        key = _derive_key(password, salt)
        try:
            ChaCha20Poly1305(key).decrypt(canary_nonce, canary_ciphertext, None)
        except InvalidTag as exc:
            raise HistoryLocked("History password is incorrect.") from exc
        self._key = key

    def _require_key(self) -> bytes:
        if self._key is None:
            raise HistoryLocked("Call unlock() with the history password first.")
        return self._key

    def record(self, message: DecryptedMessage, peer_signing_key: bytes, direction: Direction) -> None:
        if direction not in {"sent", "received"}:
            raise HistoryError("direction must be 'sent' or 'received'.")
        key = self._require_key()
        plaintext = json.dumps(
            {
                "sender_name": message.sender_name,
                "sent_at": message.sent_at.astimezone(UTC).isoformat(timespec="seconds"),
                "body": message.body,
                "attachment": (
                    message.attachment.to_dict() if message.attachment is not None else None
                ),
                "reply_to": message.reply_to,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = os.urandom(12)
        aad = _entry_aad(message.message_id, peer_signing_key, direction)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO history_entries
                    (message_id, peer_signing_key, direction, nonce, ciphertext)
                VALUES (?, ?, ?, ?, ?)
                """,
                (message.message_id, peer_signing_key, direction, nonce, ciphertext),
            )

    def entries(self) -> list[HistoryEntry]:
        key = self._require_key()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT message_id, peer_signing_key, direction, nonce, ciphertext "
                "FROM history_entries ORDER BY recorded_at"
            ).fetchall()

        results = []
        for message_id, peer_signing_key, direction, nonce, ciphertext in rows:
            try:
                aad = _entry_aad(message_id, peer_signing_key, direction)
                plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
            except InvalidTag as exc:
                raise HistoryCorrupted(f"History entry {message_id} failed authentication.") from exc
            payload = json.loads(plaintext)
            attachment = (
                AttachmentReference.from_dict(payload["attachment"])
                if payload.get("attachment") is not None
                else None
            )
            results.append(
                HistoryEntry(
                    message_id=message_id,
                    peer_signing_key=peer_signing_key,
                    direction=direction,
                    sender_name=payload["sender_name"],
                    sent_at=datetime.fromisoformat(payload["sent_at"]),
                    body=payload["body"],
                    attachment=attachment,
                    reply_to=payload.get("reply_to"),
                )
            )
        return results
