import sqlite3
from pathlib import Path

SCHEMA_VERSION = 3

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_versions (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email_normalized TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 80),
    password_record BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('direct', 'group')),
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    left_at TEXT,
    PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id TEXT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 8000),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    edited_at TEXT
);

CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    sender_id TEXT NOT NULL REFERENCES users(id),
    filename TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    status TEXT NOT NULL CHECK(status IN (
        'pending', 'verified', 'unverified', 'integrity_mismatch', 'quarantined'
    )),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    target_id TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('allowed', 'denied', 'error')),
    occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS received_message_ids (
    message_id TEXT PRIMARY KEY,
    sender_signing_key BLOB NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conversation_preferences (
    peer_signing_key BLOB PRIMARY KEY,
    pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0, 1)),
    muted INTEGER NOT NULL DEFAULT 0 CHECK(muted IN (0, 1)),
    archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
    ON messages(conversation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred
    ON audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_received_message_ids_received
    ON received_message_ids(received_at);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO schema_versions(version) VALUES (?)",
                (SCHEMA_VERSION,),
            )

    def table_names(self) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        return {row[0] for row in rows}

    def claim_message(self, message_id: str, sender_signing_key: bytes) -> bool:
        """Persist a received identifier exactly once, including across restarts."""
        with self.connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO received_message_ids(message_id, sender_signing_key)
                    VALUES (?, ?)
                    """,
                    (message_id, sender_signing_key),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def received_message_count(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM received_message_ids").fetchone()
        return int(row[0])

    def conversation_preferences(self, peer_signing_key: bytes) -> dict[str, bool]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT pinned, muted, archived FROM conversation_preferences "
                "WHERE peer_signing_key = ?",
                (peer_signing_key,),
            ).fetchone()
        if row is None:
            return {"pinned": False, "muted": False, "archived": False}
        return {"pinned": bool(row[0]), "muted": bool(row[1]), "archived": bool(row[2])}

    def update_conversation_preferences(
        self,
        peer_signing_key: bytes,
        *,
        pinned: bool,
        muted: bool,
        archived: bool,
    ) -> dict[str, bool]:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO conversation_preferences(peer_signing_key, pinned, muted, archived)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(peer_signing_key) DO UPDATE SET
                    pinned = excluded.pinned,
                    muted = excluded.muted,
                    archived = excluded.archived,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (peer_signing_key, int(pinned), int(muted), int(archived)),
            )
        return {"pinned": pinned, "muted": muted, "archived": archived}
