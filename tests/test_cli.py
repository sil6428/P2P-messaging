import argparse
from pathlib import Path

import pytest

from secure_messaging.cli import _resolve_trusted_peers, build_parser
from secure_messaging.contacts import ContactBook
from secure_messaging.identity import Identity, IdentityError


def test_identity_init_command_defaults():
    args = build_parser().parse_args(["identity", "init", "--name", "Alice"])

    assert args.identity_command == "init"
    assert args.identity == Path("identity.json")
    assert args.card == Path("peer-card.json")
    assert args.endpoint == "127.0.0.1:8765"


def test_send_command_requires_explicit_peer_and_message():
    args = build_parser().parse_args(
        ["send", "--peer", "bob.peer.json", "--message", "hello"]
    )

    assert args.peer == Path("bob.peer.json")
    assert args.message == "hello"


def test_listen_accepts_multiple_trusted_peer_cards():
    args = build_parser().parse_args(
        ["listen", "--trust", "alice.peer.json", "--trust", "bob.peer.json"]
    )

    assert args.trust == [Path("alice.peer.json"), Path("bob.peer.json")]


def test_listen_accepts_a_contacts_book_instead_of_trust_files():
    args = build_parser().parse_args(["listen", "--contacts", "contacts.db"])

    assert args.trust == []
    assert args.contacts == Path("contacts.db")


def test_send_accepts_an_attachment_path():
    args = build_parser().parse_args(
        ["send", "--peer", "bob.peer.json", "--message", "hi", "--attach", "report.pdf"]
    )

    assert args.attach == Path("report.pdf")


def test_chat_command_requires_a_peer():
    args = build_parser().parse_args(["chat", "--peer", "bob.peer.json"])

    assert args.peer == Path("bob.peer.json")
    assert args.host == "127.0.0.1"


def test_contacts_import_command():
    args = build_parser().parse_args(["contacts", "import", "alice.peer.json"])

    assert args.contacts_command == "import"
    assert args.card == Path("alice.peer.json")


def test_contacts_verify_command():
    args = build_parser().parse_args(["contacts", "verify", "ABCD 1234"])

    assert args.contacts_command == "verify"
    assert args.fingerprint == "ABCD 1234"


def test_verify_attachment_command():
    args = build_parser().parse_args(["verify-attachment", "reference.json", "downloaded.pdf"])

    assert args.reference == Path("reference.json")
    assert args.file == Path("downloaded.pdf")


def test_resolve_trusted_peers_only_includes_verified_contacts(tmp_path):
    book = ContactBook(tmp_path / "contacts.db")
    book.initialize()
    verified = Identity.create("Verified").peer_card("127.0.0.1:9001")
    unverified = Identity.create("Unverified").peer_card("127.0.0.1:9002")
    book.add(verified)
    book.add(unverified)
    book.mark_verified(verified.signing_key)

    args = argparse.Namespace(trust=[], contacts=tmp_path / "contacts.db")
    trusted = _resolve_trusted_peers(args)

    assert trusted == [verified]


def test_resolve_trusted_peers_rejects_no_trust_sources(tmp_path):
    args = argparse.Namespace(trust=[], contacts=None)

    with pytest.raises(IdentityError, match="No trusted peers"):
        _resolve_trusted_peers(args)
