import argparse
import asyncio
import getpass
import json
import threading
import webbrowser
from datetime import UTC, datetime
from pathlib import Path

import uvicorn

from secure_messaging.app import create_app
from secure_messaging.attachments import (
    AttachmentError,
    AttachmentReference,
    bind_attachment,
    verify_attachment,
)
from secure_messaging.contacts import ContactBook, ContactError
from secure_messaging.database import Database
from secure_messaging.history import HistoryError, MessageHistory
from secure_messaging.identity import Identity, IdentityError, PeerCard
from secure_messaging.protocol import DecryptedMessage, ProtocolError
from secure_messaging.transport import PeerServer, TransportError, send_message


def _add_identity_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        type=Path,
        default=Path("identity.json"),
        help="Password-protected device identity file",
    )


def _add_history_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--history",
        type=Path,
        default=None,
        help="Encrypted local history file to append delivered messages to",
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

    contacts = subparsers.add_parser("contacts", help="Manage the local contact book")
    contacts.add_argument(
        "--contacts",
        type=Path,
        default=Path("contacts.db"),
        help="Contact book database",
    )
    contacts_commands = contacts.add_subparsers(dest="contacts_command", required=True)
    contacts_import = contacts_commands.add_parser("import", help="Import a peer card, unverified by default")
    contacts_import.add_argument("card", type=Path)
    contacts_verify = contacts_commands.add_parser(
        "verify", help="Record that a fingerprint was checked out-of-band"
    )
    contacts_verify.add_argument("fingerprint", help="Full fingerprint or an unambiguous prefix")
    contacts_commands.add_parser("list", help="List imported contacts and their verification state")

    listen = subparsers.add_parser("listen", help="Listen for messages from trusted peers")
    _add_identity_argument(listen)
    _add_history_argument(listen)
    listen.add_argument(
        "--trust",
        type=Path,
        action="append",
        default=[],
        help="Trusted peer card; repeat for more than one peer",
    )
    listen.add_argument(
        "--contacts",
        type=Path,
        default=None,
        help="Contact book to also trust verified contacts from",
    )
    listen.add_argument("--database", type=Path, default=Path("peer-state.db"))
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=int, default=8765)

    send = subparsers.add_parser("send", help="Send one encrypted message to a trusted peer")
    _add_identity_argument(send)
    _add_history_argument(send)
    send.add_argument("--peer", type=Path, required=True, help="Recipient peer card")
    send.add_argument("--message", required=True, help="Message text, up to 4096 UTF-8 bytes")
    send.add_argument(
        "--attach",
        type=Path,
        default=None,
        help="Bind a local file's digest to the message without sending its bytes",
    )

    chat = subparsers.add_parser("chat", help="Interactive two-way session with one trusted peer")
    _add_identity_argument(chat)
    _add_history_argument(chat)
    chat.add_argument("--peer", type=Path, required=True, help="Peer to chat with")
    chat.add_argument("--database", type=Path, default=Path("peer-state.db"))
    chat.add_argument("--host", default="127.0.0.1")
    chat.add_argument("--port", type=int, default=8765)

    verify_attachment_parser = subparsers.add_parser(
        "verify-attachment", help="Check a received file against a message's attachment reference"
    )
    verify_attachment_parser.add_argument("reference", type=Path, help="JSON file with the attachment reference")
    verify_attachment_parser.add_argument("file", type=Path, help="Downloaded file to check")

    serve = subparsers.add_parser("serve", help="Run the development application")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--database", type=Path, default=Path("secure-messaging.db"))
    serve.add_argument("--workspace", type=Path, default=None)
    serve.add_argument("--no-open", action="store_true", help="Do not open the browser automatically")
    return parser


def _load_identity(path: Path) -> Identity:
    password = getpass.getpass(f"Password for {path}: ")
    return Identity.load(path, password)


def _open_history(path: Path | None) -> MessageHistory | None:
    if path is None:
        return None
    history = MessageHistory(path)
    history.unlock(getpass.getpass(f"History password for {path}: "))
    return history


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


def _run_contacts(args: argparse.Namespace) -> None:
    book = ContactBook(args.contacts)
    book.initialize()
    if args.contacts_command == "import":
        card = PeerCard.load(args.card)
        book.add(card)
        print(f"Imported {card.display_name} (unverified). Fingerprint: {card.fingerprint}")
        print("Verify the fingerprint with the owner over a separate channel, then run 'contacts verify'.")
    elif args.contacts_command == "verify":
        card = book.find_by_fingerprint_prefix(args.fingerprint)
        book.mark_verified(card.signing_key)
        print(f"Marked {card.display_name} as verified.")
    elif args.contacts_command == "list":
        contacts = book.all_contacts()
        if not contacts:
            print("No contacts imported yet.")
        for card, verified in contacts:
            state = "verified" if verified else "UNVERIFIED"
            print(f"[{state}] {card.display_name} ({card.endpoint}) {card.fingerprint}")


def _resolve_trusted_peers(args: argparse.Namespace) -> list[PeerCard]:
    trusted = [PeerCard.load(path) for path in args.trust]
    if args.contacts is not None:
        book = ContactBook(args.contacts)
        book.initialize()
        known = {card.signing_key for card in trusted}
        for card in book.verified_contacts():
            if card.signing_key not in known:
                trusted.append(card)
    if not trusted:
        raise IdentityError("No trusted peers: pass --trust or a --contacts book with verified contacts.")
    return trusted


async def _listen(args: argparse.Namespace) -> None:
    identity = _load_identity(args.identity)
    trusted_peers = _resolve_trusted_peers(args)
    history = _open_history(args.history)

    def show_message(message: DecryptedMessage) -> None:
        timestamp = message.sent_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n[{timestamp}] {message.sender_name}: {message.body}")
        if message.attachment is not None:
            print(f"  attachment: {message.attachment.filename} ({message.attachment.sha256})")
        if history is not None:
            history.record(message, message.sender_signing_key, "received")

    server = PeerServer(identity, trusted_peers, Database(args.database), show_message)
    await server.start(args.host, args.port)
    print(f"Listening on {args.host}:{server.port}. Press Ctrl+C to stop.")
    try:
        await server.serve_forever()
    finally:
        await server.close()


def _build_attachment(path: Path | None) -> AttachmentReference | None:
    if path is None:
        return None
    reference = bind_attachment(path)
    print(f"Attachment reference: {json.dumps(reference.to_dict())}")
    print("Share the file itself out-of-band; only its digest is sent in the message.")
    return reference


def _record_sent_message(
    history: MessageHistory | None,
    identity: Identity,
    peer: PeerCard,
    acknowledgement: DecryptedMessage,
    body: str,
    attachment: AttachmentReference | None = None,
) -> None:
    if history is None:
        return
    if not acknowledgement.reply_to:
        raise HistoryError("Delivery acknowledgement did not identify the sent message.")
    history.record(
        DecryptedMessage(
            message_id=acknowledgement.reply_to,
            sender_name=identity.display_name,
            sent_at=datetime.now(UTC),
            kind="message",
            body=body,
            reply_to=None,
            sender_signing_key=identity.signing_public_key,
            attachment=attachment,
        ),
        peer.signing_key,
        "sent",
    )


async def _send(args: argparse.Namespace) -> None:
    identity = _load_identity(args.identity)
    peer = PeerCard.load(args.peer)
    history = _open_history(args.history)
    attachment = _build_attachment(args.attach)
    acknowledgement = await send_message(identity, peer, args.message, attachment=attachment)
    print(f"Encrypted acknowledgement received from {acknowledgement.sender_name}.")
    _record_sent_message(history, identity, peer, acknowledgement, args.message, attachment)


async def _chat(args: argparse.Namespace) -> None:
    identity = _load_identity(args.identity)
    peer = PeerCard.load(args.peer)
    history = _open_history(args.history)

    def show_message(message: DecryptedMessage) -> None:
        if message.kind != "message":
            return
        timestamp = message.sent_at.strftime("%H:%M:%S")
        print(f"\n[{timestamp}] {message.sender_name}: {message.body}\n> ", end="", flush=True)
        if history is not None:
            history.record(message, message.sender_signing_key, "received")

    server = PeerServer(identity, [peer], Database(args.database), show_message)
    await server.start(args.host, args.port)
    print(f"Chatting as {identity.display_name}. Listening on {args.host}:{server.port}.")
    print("Type a message and press Enter to send. Ctrl+C to quit.")

    loop = asyncio.get_running_loop()
    try:
        while True:
            line = await loop.run_in_executor(None, input, "> ")
            if not line.strip():
                continue
            try:
                acknowledgement = await send_message(identity, peer, line)
            except TransportError as exc:
                print(f"Could not deliver message: {exc}")
                continue
            _record_sent_message(history, identity, peer, acknowledgement, line)
    except (KeyboardInterrupt, EOFError):
        print("\nClosing chat.")
    finally:
        await server.close()


def _run_verify_attachment(args: argparse.Namespace) -> None:
    reference = AttachmentReference.from_dict(json.loads(args.reference.read_text(encoding="utf-8")))
    status = verify_attachment(reference, args.file)
    print(f"{args.file}: {status.value}")
    if status.value != "verified":
        raise SystemExit(1)


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
        elif args.command == "contacts":
            _run_contacts(args)
        elif args.command == "listen":
            asyncio.run(_listen(args))
        elif args.command == "send":
            asyncio.run(_send(args))
        elif args.command == "chat":
            asyncio.run(_chat(args))
        elif args.command == "verify-attachment":
            _run_verify_attachment(args)
        elif args.command == "serve":
            if args.host not in {"127.0.0.1", "localhost", "::1"}:
                raise SystemExit(
                    "The browser interface may only bind to this computer. "
                    "Configure the peer-card endpoint for LAN messaging instead."
                )
            if not args.no_open:
                browser_host = "127.0.0.1" if args.host == "::1" else args.host
                threading.Timer(
                    0.8,
                    webbrowser.open,
                    args=(f"http://{browser_host}:{args.port}",),
                ).start()
            uvicorn.run(
                create_app(args.database, args.workspace),
                host=args.host,
                port=args.port,
            )
    except (AttachmentError, ContactError, HistoryError, IdentityError, ProtocolError, TransportError) as exc:
        raise SystemExit(f"Error: {exc}") from exc
