import pytest

from secure_messaging.contacts import ContactBook, ContactError
from secure_messaging.identity import Identity


def make_card(name: str = "Alice"):
    return Identity.create(name).peer_card("127.0.0.1:9001")


def test_imported_contact_is_unverified_by_default(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()
    card = make_card()

    book.add(card)

    assert book.is_verified(card.signing_key) is False
    assert book.verified_contacts() == []
    assert book.get(card.signing_key) == card


def test_marking_verified_adds_it_to_the_trust_list(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()
    card = make_card()
    book.add(card)

    book.mark_verified(card.signing_key)

    assert book.is_verified(card.signing_key) is True
    assert book.verified_contacts() == [card]


def test_verifying_unknown_contact_is_rejected(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()

    with pytest.raises(ContactError, match="Unknown contact"):
        book.mark_verified(b"\x00" * 32)


def test_reimporting_a_contact_does_not_clear_verification(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()
    identity = Identity.create("Alice")
    card = identity.peer_card("127.0.0.1:9001")
    book.add(card)
    book.mark_verified(card.signing_key)

    moved = identity.peer_card("127.0.0.1:9999")
    book.add(moved)

    assert book.is_verified(card.signing_key) is True
    assert book.get(card.signing_key).endpoint == "127.0.0.1:9999"


def test_find_by_fingerprint_prefix(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()
    card = make_card()
    book.add(card)

    found = book.find_by_fingerprint_prefix(card.fingerprint[:9])

    assert found == card


def test_find_by_fingerprint_prefix_rejects_unknown_prefix(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()

    with pytest.raises(ContactError, match="No contact matches"):
        book.find_by_fingerprint_prefix("FFFF")
