import argparse
import asyncio
import getpass
from pathlib import Path

import uvicorn

from secure_messaging.database import Database
from secure_messaging.identity import Identity, IdentityError, PeerCard
from secure_messaging.protocol import ProtocolError
from secure_messaging.transport import PeerServer, TransportError, send_message


def _add_identity_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        type=Path,
        default=Path("identity.json"),
        help="Password-protected device identity file",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure Messaging Platform educational peer demo")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity", help="Create or inspect peer identities")
    identity_commands = identity.add_subparsers(dest="identity_command", required=True)
    identity_init = identity_commands.add_parser("init", help="Create a password-protected identity")
    identity_init.add_argument("--name", required=True, help="Display name shown to trusted peers")
    _add_identity_argument(identity_init)
    identity_init.add_argument(
        "--card",
        type=Path,
        default=Path("peer-card.json"),
        help="Public peer card to share",
    )
    identity_init.add_argument(
        "--endpoint",
        default="127.0.0.1:8765",
        help="Reachable host:port written into the public peer card",
    )
    identity_show = identity_commands.add_parser("show", help="Verify and display a peer card")
    identity_show.add_argument("card", type=Path)

    listen = subparsers.add_parser("listen", help="Listen for messages from trusted peers")
    _add_identity_argument(listen)
    listen.add_argument(
        "--trust",
        type=Path,
        action="append",
        required=True,
        help="Trusted peer card; repeat for more than one peer",
    )
    listen.add_argument("--database", type=Path, default=Path("peer-state.db"))
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=int, default=8765)

    send = subparsers.add_parser("send", help="Send one encrypted message to a trusted peer")
    _add_identity_argument(send)
    send.add_argument("--peer", type=Path, required=True, help="Recipient peer card")
    send.add_argument("--message", required=True, help="Message text, up to 4096 UTF-8 bytes")

    serve = subparsers.add_parser("serve", help="Run the development application")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def _load_identity(path: Path) -> Identity:
    password = getpass.getpass(f"Password for {path}: ")
    return Identity.load(path, password)


def _create_identity(args: argparse.Namespace) -> None:
    if args.identity.exists():
        raise IdentityError(f"Refusing to replace existing identity: {args.identity}")
    password = getpass.getpass("New identity password (at least 12 characters): ")
    confirmation = getpass.getpass("Confirm identity password: ")
    if password != confirmation:
        raise IdentityError("Passwords did not match.")
    identity = Identity.create(args.name)
    identity.save(args.identity, password)
    card = identity.peer_card(args.endpoint)
    card.save(args.card)
    print(f"Created private identity: {args.identity}")
    print(f"Share only this peer card: {args.card}")
    print(f"Verify this fingerprint separately: {card.fingerprint}")


async def _listen(args: argparse.Namespace) -> None:
    identity = _load_identity(args.identity)
    trusted_peers = [PeerCard.load(path) for path in args.trust]

    def show_message(message) -> None:
        timestamp = message.sent_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n[{timestamp}] {message.sender_name}: {message.body}")

    server = PeerServer(identity, trusted_peers, Database(args.database), show_message)
    await server.start(args.host, args.port)
    print(f"Listening on {args.host}:{server.port}. Press Ctrl+C to stop.")
    try:
        await server.serve_forever()
    finally:
        await server.close()


async def _send(args: argparse.Namespace) -> None:
    identity = _load_identity(args.identity)
    peer = PeerCard.load(args.peer)
    acknowledgement = await send_message(identity, peer, args.message)
    print(f"Encrypted acknowledgement received from {acknowledgement.sender_name}.")


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.command == "identity" and args.identity_command == "init":
            _create_identity(args)
        elif args.command == "identity" and args.identity_command == "show":
            card = PeerCard.load(args.card)
            print(f"Name: {card.display_name}")
            print(f"Endpoint: {card.endpoint}")
            print(f"Fingerprint: {card.fingerprint}")
        elif args.command == "listen":
            asyncio.run(_listen(args))
        elif args.command == "send":
            asyncio.run(_send(args))
        elif args.command == "serve":
            uvicorn.run("secure_messaging.app:app", host=args.host, port=args.port)
    except (IdentityError, ProtocolError, TransportError) as exc:
        raise SystemExit(f"Error: {exc}") from exc
