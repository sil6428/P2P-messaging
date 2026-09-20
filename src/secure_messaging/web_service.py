from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from secure_messaging.attachments import AttachmentReference
from secure_messaging.contacts import ContactBook, ContactError
from secure_messaging.database import Database
from secure_messaging.history import HistoryEntry, MessageHistory
from secure_messaging.identity import Identity, PeerCard, parse_endpoint
from secure_messaging.protocol import DecryptedMessage
from secure_messaging.transport import PeerServer, send_message

SESSION_LIFETIME = timedelta(hours=8)


@dataclass(frozen=True, slots=True)
class WorkspacePaths:
    root: Path
    identity: Path
    peer_card: Path
    contacts: Path
    history: Path
    peer_state: Path

    @classmethod
    def from_database(cls, database_path: str | Path) -> WorkspacePaths:
        database = Path(database_path)
        root = database.parent / f"{database.stem}-workspace"
        return cls(
            root=root,
            identity=root / "identity.json",
            peer_card=root / "peer-card.json",
            contacts=root / "contacts.db",
            history=root / "history.db",
            peer_state=root / "peer-state.db",
        )


@dataclass(slots=True)
class LocalSession:
    token: str
    csrf_token: str
    expires_at: datetime
    identity: Identity
    history: MessageHistory


class LocalMessagingService:
    """Single-device application state for the local browser interface.

    Private keys and the history key exist only in process memory while the user is
    signed in. Browser sessions deliberately expire when the process exits.
    """

    def __init__(self, database: Database, paths: WorkspacePaths) -> None:
        self.database = database
        self.paths = paths
        self.contacts = ContactBook(paths.contacts)
        self.sessions: dict[str, LocalSession] = {}
        self.listener: PeerServer | None = None
        self.listener_owner: str | None = None
        self.listener_error: str | None = None

    def initialize(self) -> None:
        self.paths.root.mkdir(parents=True, exist_ok=True)
        self.contacts.initialize()

    @property
    def setup_required(self) -> bool:
        return not self.paths.identity.exists()

    def setup(
        self,
        display_name: str,
        password: str,
        history_password: str,
        endpoint: str,
    ) -> LocalSession:
        if not self.setup_required:
            raise ValueError("This device already has an identity.")
        parse_endpoint(endpoint)
        identity = Identity.create(display_name)
        identity.save(self.paths.identity, password)
        identity.peer_card(endpoint).save(self.paths.peer_card)
        history = MessageHistory(self.paths.history)
        history.unlock(history_password)
        return self._new_session(identity, history)

    def login(self, password: str, history_password: str) -> LocalSession:
        if self.setup_required:
            raise ValueError("Complete first-time setup before signing in.")
        identity = Identity.load(self.paths.identity, password)
        history = MessageHistory(self.paths.history)
        history.unlock(history_password)
        return self._new_session(identity, history)

    def _new_session(self, identity: Identity, history: MessageHistory) -> LocalSession:
        # Relay is a single-device application. A fresh unlock invalidates any
        # previously issued browser token instead of leaving parallel sessions.
        self.sessions.clear()
        session = LocalSession(
            token=secrets.token_urlsafe(32),
            csrf_token=secrets.token_urlsafe(24),
            expires_at=datetime.now(UTC) + SESSION_LIFETIME,
            identity=identity,
            history=history,
        )
        self.sessions[session.token] = session
        self._remove_expired_sessions()
        return session

    def _remove_expired_sessions(self) -> None:
        now = datetime.now(UTC)
        self.sessions = {
            token: session
            for token, session in self.sessions.items()
            if session.expires_at > now
        }

    def get_session(self, token: str | None) -> LocalSession | None:
        if not token:
            return None
        session = self.sessions.get(token)
        if session is None or session.expires_at <= datetime.now(UTC):
            self.sessions.pop(token, None)
            return None
        return session

    async def logout(self, token: str) -> None:
        self.sessions.pop(token, None)
        if self.listener_owner == token:
            await self.stop_listener()

    async def stop_listener(self) -> None:
        if self.listener is not None:
            await self.listener.close()
        self.listener = None
        self.listener_owner = None

    async def start_listener(self, session: LocalSession) -> None:
        await self.stop_listener()
        card = PeerCard.load(self.paths.peer_card)
        bind_host, port = parse_endpoint(card.endpoint)

        def record_received(message: DecryptedMessage) -> None:
            session.history.record(message, message.sender_signing_key, "received")

        listener = PeerServer(
            session.identity,
            self.contacts.verified_contacts(),
            Database(self.paths.peer_state),
            record_received,
        )
        try:
            await listener.start(bind_host, port)
        except OSError as exc:
            self.listener_error = f"Could not listen on local port {port}: {exc}"
            return
        self.listener = listener
        self.listener_owner = session.token
        self.listener_error = None

    def listener_status(self) -> dict[str, str | int | bool | None]:
        if self.listener is None:
            return {"online": False, "port": None, "error": self.listener_error}
        return {"online": True, "port": self.listener.port, "error": None}

    def profile(self, session: LocalSession) -> dict[str, str]:
        card = PeerCard.load(self.paths.peer_card)
        return {
            "display_name": session.identity.display_name,
            "endpoint": card.endpoint,
            "fingerprint": card.fingerprint,
            "peer_card": card.to_json(),
        }

    def contact_summaries(self, session: LocalSession) -> list[dict[str, object]]:
        entries = session.history.entries()
        latest_by_peer: dict[bytes, HistoryEntry] = {}
        counts: dict[bytes, int] = {}
        for entry in entries:
            latest_by_peer[entry.peer_signing_key] = entry
            counts[entry.peer_signing_key] = counts.get(entry.peer_signing_key, 0) + 1

        contacts = []
        for card, verified in self.contacts.all_contacts():
            latest = latest_by_peer.get(card.signing_key)
            preferences = self.database.conversation_preferences(card.signing_key)
            contacts.append(
                {
                    "id": card.signing_key.hex(),
                    "display_name": card.display_name,
                    "endpoint": card.endpoint,
                    "fingerprint": card.fingerprint,
                    "verified": verified,
                    "message_count": counts.get(card.signing_key, 0),
                    "last_message": latest.body if latest is not None else None,
                    "last_message_at": (
                        latest.sent_at.isoformat() if latest is not None else None
                    ),
                    **preferences,
                }
            )
        contacts.sort(key=lambda item: str(item["last_message_at"] or ""), reverse=True)
        contacts.sort(key=lambda item: not bool(item["pinned"]))
        return contacts

    def import_contact(self, peer_card_json: str) -> PeerCard:
        card = PeerCard.from_json(peer_card_json)
        own_card = PeerCard.load(self.paths.peer_card)
        if card.signing_key == own_card.signing_key:
            raise ContactError("You cannot add this device as its own contact.")
        self.contacts.add(card)
        return card

    def verify_contact(self, fingerprint: str) -> PeerCard:
        card = self.contacts.find_by_fingerprint_prefix(fingerprint)
        self.contacts.mark_verified(card.signing_key)
        return card

    def _contact_from_id(self, contact_id: str) -> tuple[PeerCard, bool]:
        try:
            signing_key = bytes.fromhex(contact_id)
        except ValueError as exc:
            raise ContactError("Contact identifier is invalid.") from exc
        if len(signing_key) != 32:
            raise ContactError("Contact identifier is invalid.")
        card = self.contacts.get(signing_key)
        if card is None:
            raise ContactError("Contact was not found.")
        return card, self.contacts.is_verified(signing_key)

    def conversation(
        self,
        session: LocalSession,
        contact_id: str,
        query: str = "",
    ) -> dict[str, object]:
        card, verified = self._contact_from_id(contact_id)
        clean_query = query.casefold().strip()
        entries = [
            entry
            for entry in session.history.entries()
            if entry.peer_signing_key == card.signing_key
            and (not clean_query or clean_query in entry.body.casefold())
        ]
        return {
            "contact": {
                "id": contact_id,
                "display_name": card.display_name,
                "endpoint": card.endpoint,
                "fingerprint": card.fingerprint,
                "verified": verified,
                **self.database.conversation_preferences(card.signing_key),
            },
            "messages": [self._serialize_entry(entry) for entry in entries],
        }

    @staticmethod
    def _serialize_entry(entry: HistoryEntry) -> dict[str, object]:
        return {
            "id": entry.message_id,
            "direction": entry.direction,
            "sender_name": entry.sender_name,
            "sent_at": entry.sent_at.isoformat(),
            "body": entry.body,
            "status": "acknowledged" if entry.direction == "sent" else "received",
            "attachment": entry.attachment.to_dict() if entry.attachment else None,
            "reply_to": entry.reply_to,
        }

    async def send(
        self,
        session: LocalSession,
        contact_id: str,
        body: str,
        attachment: AttachmentReference | None,
        reply_to: str | None,
    ) -> dict[str, object]:
        card, verified = self._contact_from_id(contact_id)
        if not verified:
            raise ContactError("Verify this contact's fingerprint before sending messages.")
        if reply_to is not None and not any(
            entry.message_id == reply_to and entry.peer_signing_key == card.signing_key
            for entry in session.history.entries()
        ):
            raise ValueError("The message being replied to is not in this conversation.")
        acknowledgement = await send_message(
            session.identity,
            card,
            body,
            attachment=attachment,
            reply_to=reply_to,
        )
        if acknowledgement.reply_to is None:
            raise ValueError("The peer acknowledgement did not identify the message.")
        sent = DecryptedMessage(
            message_id=acknowledgement.reply_to,
            sender_name=session.identity.display_name,
            sent_at=datetime.now(UTC),
            kind="message",
            body=body,
            reply_to=reply_to,
            sender_signing_key=session.identity.signing_public_key,
            attachment=attachment,
        )
        session.history.record(sent, card.signing_key, "sent")
        return self._serialize_entry(
            HistoryEntry(
                message_id=sent.message_id,
                peer_signing_key=card.signing_key,
                direction="sent",
                sender_name=sent.sender_name,
                sent_at=sent.sent_at,
                body=sent.body,
                attachment=attachment,
                reply_to=reply_to,
            )
        )

    def update_preferences(
        self,
        contact_id: str,
        *,
        pinned: bool,
        muted: bool,
        archived: bool,
    ) -> dict[str, bool]:
        card, _ = self._contact_from_id(contact_id)
        return self.database.update_conversation_preferences(
            card.signing_key,
            pinned=pinned,
            muted=muted,
            archived=archived,
        )
