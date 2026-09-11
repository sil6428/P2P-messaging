from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from secure_messaging.identity import Identity, IdentityError, PeerCard
from secure_messaging.protocol import (
    AuthenticationError,
    ProtocolError,
    decrypt_message,
    encrypt_message,
)


def make_peers():
    alice = Identity.create("Alice")
    bob = Identity.create("Bob")
    return alice, alice.peer_card("127.0.0.1:9001"), bob, bob.peer_card("127.0.0.1:9002")


def test_peer_card_round_trip_and_fingerprint():
    _, alice_card, _, _ = make_peers()

    restored = PeerCard.from_json(alice_card.to_json())

    assert restored == alice_card
    assert len(restored.fingerprint.split()) == 16


def test_peer_card_rejects_edits_after_signing():
    _, alice_card, _, _ = make_peers()
    changed = replace(alice_card, display_name="Mallory")

    with pytest.raises(IdentityError, match="signature"):
        changed.verify()


def test_password_protected_identity_round_trip(tmp_path):
    alice, _, _, _ = make_peers()
    path = tmp_path / "alice.identity.json"

    alice.save(path, "correct horse battery staple")
    restored = Identity.load(path, "correct horse battery staple")

    assert restored.display_name == "Alice"
    assert restored.signing_public_key == alice.signing_public_key
    assert b"PRIVATE KEY" not in path.read_bytes()


def test_identity_rejects_wrong_password(tmp_path):
    alice, _, _, _ = make_peers()
    path = tmp_path / "alice.identity.json"
    alice.save(path, "correct horse battery staple")

    with pytest.raises(IdentityError, match="password"):
        Identity.load(path, "not the right password")


def test_encrypted_message_round_trip():
    alice, alice_card, bob, bob_card = make_peers()

    envelope = encrypt_message(alice, bob_card, "hello Bob")
    message = decrypt_message(bob, alice_card, envelope)

    assert message.body == "hello Bob"
    assert message.kind == "message"
    assert message.sender_name == "Alice"


def test_ciphertext_tampering_is_rejected():
    alice, alice_card, bob, bob_card = make_peers()
    envelope = encrypt_message(alice, bob_card, "original")
    tampered = replace(envelope, ciphertext=envelope.ciphertext[:-1] + b"0")

    with pytest.raises(AuthenticationError):
        decrypt_message(bob, alice_card, tampered)


def test_wrong_recipient_is_rejected():
    alice, alice_card, _, bob_card = make_peers()
    charlie = Identity.create("Charlie")

    envelope = encrypt_message(alice, bob_card, "for Bob")

    with pytest.raises(AuthenticationError, match="another recipient"):
        decrypt_message(charlie, alice_card, envelope)


def test_expired_message_is_rejected():
    alice, alice_card, bob, bob_card = make_peers()
    sent_at = datetime(2026, 1, 1, tzinfo=UTC)
    envelope = encrypt_message(alice, bob_card, "old", sent_at=sent_at)

    with pytest.raises(ProtocolError, match="expired"):
        decrypt_message(
            bob,
            alice_card,
            envelope,
            now=sent_at + timedelta(days=8),
        )


def test_message_size_is_bounded():
    alice, _, _, bob_card = make_peers()

    with pytest.raises(ProtocolError, match="4096"):
        encrypt_message(alice, bob_card, "x" * 4097)
