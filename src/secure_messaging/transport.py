from __future__ import annotations

import asyncio
import inspect
import json
import struct
from collections.abc import Awaitable, Callable, Iterable

from secure_messaging.database import Database
from secure_messaging.identity import Identity, PeerCard, parse_endpoint
from secure_messaging.protocol import (
    DecryptedMessage,
    EncryptedEnvelope,
    ProtocolError,
    decrypt_message,
    encrypt_message,
)

MAX_FRAME_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
MessageHandler = Callable[[DecryptedMessage], Awaitable[None] | None]


class TransportError(ConnectionError):
    """Raised when a peer connection or delivery acknowledgement fails."""


class DeliveryRejected(TransportError):
    """Raised when a peer rejects a message without exposing internal details."""


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    (length,) = struct.unpack(">I", header)
    if not 1 <= length <= MAX_FRAME_BYTES:
        raise TransportError("Peer frame length is outside the allowed range.")
    return await reader.readexactly(length)


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if not 1 <= len(payload) <= MAX_FRAME_BYTES:
        raise TransportError("Peer frame length is outside the allowed range.")
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


class PeerServer:
    def __init__(
        self,
        identity: Identity,
        trusted_peers: Iterable[PeerCard],
        database: Database,
        on_message: MessageHandler | None = None,
    ) -> None:
        self.identity = identity
        self.database = database
        self.on_message = on_message
        self._server: asyncio.AbstractServer | None = None
        self._trusted_peers: dict[bytes, PeerCard] = {}
        for peer in trusted_peers:
            peer.verify()
            self._trusted_peers[peer.signing_key] = peer

    async def start(self, host: str, port: int) -> None:
        self.database.initialize()
        self._server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
            limit=MAX_FRAME_BYTES + 4,
        )

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Peer server has not started.")
        return int(self._server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("Peer server has not started.")
        async with self._server:
            await self._server.serve_forever()

    async def _send_rejection(self, writer: asyncio.StreamWriter) -> None:
        payload = json.dumps({"error": "rejected"}, separators=(",", ":")).encode("utf-8")
        try:
            await write_frame(writer, payload)
        except (ConnectionError, TransportError):
            pass

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw_envelope = await read_frame(reader)
            envelope = EncryptedEnvelope.from_json(raw_envelope)
            sender = self._trusted_peers.get(envelope.sender_signing_key)
            if sender is None:
                raise DeliveryRejected("Unknown peer.")
            message = decrypt_message(self.identity, sender, envelope)
            if message.kind != "message":
                raise DeliveryRejected("Only direct messages are accepted.")
            if not self.database.claim_message(message.message_id, sender.signing_key):
                raise DeliveryRejected("Message was already received.")
            if self.on_message is not None:
                result = self.on_message(message)
                if inspect.isawaitable(result):
                    await result
            acknowledgement = encrypt_message(
                self.identity,
                sender,
                "accepted",
                kind="ack",
                reply_to=message.message_id,
            )
            await write_frame(writer, acknowledgement.to_json().encode("utf-8"))
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
            ProtocolError,
            TransportError,
            ValueError,
        ):
            await self._send_rejection(writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def send_message(
    identity: Identity,
    peer: PeerCard,
    body: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> DecryptedMessage:
    peer.verify()
    host, port = parse_endpoint(peer.endpoint)
    envelope = encrypt_message(identity, peer, body)

    async def exchange() -> DecryptedMessage:
        try:
            reader, writer = await asyncio.open_connection(host, port, limit=MAX_FRAME_BYTES + 4)
        except OSError as exc:
            raise TransportError("Could not connect to the peer.") from exc
        try:
            await write_frame(writer, envelope.to_json().encode("utf-8"))
            raw_response = await read_frame(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        try:
            response = json.loads(raw_response)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DeliveryRejected("Peer returned an invalid response.") from exc
        if isinstance(response, dict) and response.get("error") == "rejected":
            raise DeliveryRejected("Peer rejected the message.")
        acknowledgement = EncryptedEnvelope.from_dict(response)
        message = decrypt_message(identity, peer, acknowledgement)
        if message.kind != "ack" or message.reply_to != envelope.message_id:
            raise DeliveryRejected("Peer acknowledgement did not match the message.")
        return message

    try:
        return await asyncio.wait_for(exchange(), timeout=timeout_seconds)
    except TimeoutError as exc:
        raise TransportError("Peer did not respond before the timeout.") from exc
