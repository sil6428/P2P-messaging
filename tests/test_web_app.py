import socket
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from secure_messaging.app import create_app
from secure_messaging.identity import Identity
from secure_messaging.protocol import DecryptedMessage


def available_port() -> int:
    with socket.socket() as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


def setup_client(client: TestClient, port: int) -> dict:
    response = client.post(
        "/api/setup",
        json={
            "display_name": "Alice",
            "password": "correct horse battery staple",
            "history_password": "separate history password",
            "endpoint": f"127.0.0.1:{port}",
        },
    )
    assert response.status_code == 201
    return response.json()


def test_browser_setup_contact_verification_and_conversation_controls(tmp_path):
    app = create_app(tmp_path / "app.db", tmp_path / "workspace")
    with TestClient(app) as client:
        assert "Relay" in client.get("/").text
        assert client.get("/api/session").json() == {
            "authenticated": False,
            "setup_required": True,
        }

        setup = setup_client(client, available_port())
        csrf = setup["csrf_token"]
        assert setup["listener"]["online"] is True
        assert client.get("/api/session").json()["authenticated"] is True

        bob = Identity.create("Bob")
        bob_card = bob.peer_card("127.0.0.1:9999")
        missing_csrf = client.post("/api/contacts", json={"peer_card": bob_card.to_json()})
        assert missing_csrf.status_code == 403

        imported = client.post(
            "/api/contacts",
            headers={"X-CSRF-Token": csrf},
            json={"peer_card": bob_card.to_json()},
        )
        assert imported.status_code == 201
        contact_id = imported.json()["id"]
        assert imported.json()["verified"] is False

        verified = client.post(
            "/api/contacts/verify",
            headers={"X-CSRF-Token": csrf},
            json={"fingerprint": bob_card.fingerprint[:9]},
        )
        assert verified.status_code == 200
        assert verified.json()["verified"] is True

        session_token = client.cookies.get("smp_session")
        session = app.state.messaging.get_session(session_token)
        message = DecryptedMessage(
            message_id="browser-visible-message",
            sender_name="Bob",
            sent_at=datetime.now(UTC),
            kind="message",
            body="authenticated hello",
            reply_to=None,
            sender_signing_key=bob.signing_public_key,
        )
        session.history.record(message, bob.signing_public_key, "received")

        conversation = client.get(f"/api/conversations/{contact_id}")
        assert conversation.status_code == 200
        assert conversation.json()["messages"][0]["body"] == "authenticated hello"
        assert client.get(
            f"/api/conversations/{contact_id}", params={"q": "missing"}
        ).json()["messages"] == []

        preferences = client.put(
            f"/api/conversations/{contact_id}/preferences",
            headers={"X-CSRF-Token": csrf},
            json={"pinned": True, "muted": True, "archived": False},
        )
        assert preferences.json() == {"pinned": True, "muted": True, "archived": False}
        [contact] = client.get("/api/contacts").json()["contacts"]
        assert contact["pinned"] is True
        assert contact["verified"] is True

        logged_out = client.post("/api/logout", headers={"X-CSRF-Token": csrf})
        assert logged_out.status_code == 204
        assert client.get("/api/contacts").status_code == 401


def test_browser_login_rejects_wrong_secrets_and_unlocks_existing_device(tmp_path):
    app = create_app(tmp_path / "app.db", tmp_path / "workspace")
    with TestClient(app) as client:
        setup = setup_client(client, available_port())
        client.post("/api/logout", headers={"X-CSRF-Token": setup["csrf_token"]})

        rejected = client.post(
            "/api/login",
            json={"password": "wrong", "history_password": "also wrong"},
        )
        assert rejected.status_code == 401

        unlocked = client.post(
            "/api/login",
            json={
                "password": "correct horse battery staple",
                "history_password": "separate history password",
            },
        )
        assert unlocked.status_code == 200
        assert unlocked.json()["profile"]["display_name"] == "Alice"
