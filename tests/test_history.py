import pytest

from secure_messaging.history import HistoryCorrupted, HistoryLocked, MessageHistory
from secure_messaging.identity import Identity
from secure_messaging.protocol import decrypt_message, encrypt_message


def make_message():
    alice = Identity.create("Alice")
    bob = Identity.create("Bob")
    alice_card = alice.peer_card("127.0.0.1:9001")
    bob_card = bob.peer_card("127.0.0.1:9002")
    envelope = encrypt_message(alice, bob_card, "hello Bob")
    return decrypt_message(bob, alice_card, envelope), alice_card.signing_key


def test_recorded_message_round_trips(tmp_path):
    path = tmp_path / "history.db"
    message, peer_key = make_message()

    history = MessageHistory(path)
    history.unlock("correct horse battery staple")
    history.record(message, peer_key, "received")

    reopened = MessageHistory(path)
    reopened.unlock("correct horse battery staple")
    entries = reopened.entries()

    assert len(entries) == 1
    assert entries[0].body == "hello Bob"
    assert entries[0].sender_name == "Alice"
    assert entries[0].direction == "received"
    assert entries[0].peer_signing_key == peer_key


def test_wrong_password_is_rejected_immediately(tmp_path):
    path = tmp_path / "history.db"
    message, peer_key = make_message()
    history = MessageHistory(path)
    history.unlock("correct horse battery staple")
    history.record(message, peer_key, "sent")

    locked_out = MessageHistory(path)
    with pytest.raises(HistoryLocked):
        locked_out.unlock("wrong password entirely")


def test_reading_before_unlock_is_rejected(tmp_path):
    history = MessageHistory(tmp_path / "history.db")

    with pytest.raises(HistoryLocked):
        history.entries()


def test_corrupted_entry_is_detected_on_read(tmp_path):
    import sqlite3

    path = tmp_path / "history.db"
    message, peer_key = make_message()
    history = MessageHistory(path)
    history.unlock("correct horse battery staple")
    history.record(message, peer_key, "received")

    with sqlite3.connect(path) as connection:
        (ciphertext,) = connection.execute(
            "SELECT ciphertext FROM history_entries WHERE message_id = ?",
            (message.message_id,),
        ).fetchone()
        connection.execute(
            "UPDATE history_entries SET ciphertext = ? WHERE message_id = ?",
            (ciphertext + b"\x00", message.message_id),
        )

    reopened = MessageHistory(path)
    reopened.unlock("correct horse battery staple")
    with pytest.raises(HistoryCorrupted):
        reopened.entries()


def test_empty_store_unlocks_with_any_password(tmp_path):
    history = MessageHistory(tmp_path / "history.db")

    history.unlock("first password used")

    assert history.entries() == []
