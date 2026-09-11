from pathlib import Path

from secure_messaging.cli import build_parser


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
