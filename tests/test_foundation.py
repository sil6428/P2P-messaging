from fastapi.testclient import TestClient

from secure_messaging.app import create_app
from secure_messaging.database import Database


def test_status_identifies_incomplete_development_state(tmp_path):
    app = create_app(tmp_path / "messages.db")
    with TestClient(app) as client:
        response = client.get("/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "development"
    assert "messaging" not in payload["available_features"]
    assert "No authentication" in payload["warning"]


def test_initialization_creates_expected_security_boundaries(tmp_path):
    database = Database(tmp_path / "messages.db")
    database.initialize()

    assert {
        "schema_versions",
        "users",
        "sessions",
        "conversations",
        "conversation_members",
        "messages",
        "attachments",
        "audit_events",
    }.issubset(database.table_names())


def test_initialization_is_idempotent(tmp_path):
    database = Database(tmp_path / "messages.db")
    database.initialize()
    database.initialize()

    with database.connect() as connection:
        count = connection.execute("SELECT COUNT(*) FROM schema_versions").fetchone()[0]

    assert count == 1


def test_foreign_keys_are_enabled_for_each_connection(tmp_path):
    database = Database(tmp_path / "messages.db")
    database.initialize()

    with database.connect() as connection:
        enabled = connection.execute("PRAGMA foreign_keys").fetchone()[0]

    assert enabled == 1

