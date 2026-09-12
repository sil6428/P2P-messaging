import asyncio
import json
import struct

import pytest

from secure_messaging.database import Database
from secure_messaging.identity import Identity
from secure_messaging.protocol import encrypt_message
from secure_messaging.transport import (
    DeliveryRejected,
    PeerServer,
    TransportError,
    read_frame,
    send_message,
    write_frame,
)


def test_replay_claim_persists_across_database_instances(tmp_path):
    path = tmp_path / "messages.db"
    first = Database(path)
    first.initialize()

    assert first.claim_message("one-message", b"sender") is True
    assert Database(path).claim_message("one-message", b"sender") is False
    assert Database(path).received_message_count() == 1


def test_read_frame_rejects_oversized_payload_before_body_read():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack(">I", 70_000))
        reader.feed_eof()
        with pytest.raises(TransportError, match="allowed range"):
            await read_frame(reader)

    asyncio.run(scenario())


def test_write_frame_rejects_empty_payload():
    class Writer:
        def write(self, _: bytes):
            raise AssertionError("empty frame must be rejected before write")

        async def drain(self):
            raise AssertionError("empty frame must be rejected before drain")

    with pytest.raises(TransportError, match="allowed range"):
        asyncio.run(write_frame(Writer(), b""))


def test_two_peers_exchange_message_and_authenticated_ack(tmp_path):
    async def scenario():
        alice = Identity.create("Alice")
        bob = Identity.create("Bob")
        alice_card = alice.peer_card("127.0.0.1:9001")
        received = []
        server = PeerServer(
            bob,
            [alice_card],
            Database(tmp_path / "bob.db"),
            received.append,
        )
        await server.start("127.0.0.1", 0)
        try:
            bob_card = bob.peer_card(f"127.0.0.1:{server.port}")
            acknowledgement = await send_message(alice, bob_card, "hello from Alice")
        finally:
            await server.close()

        assert [message.body for message in received] == ["hello from Alice"]
        assert acknowledgement.kind == "ack"
        assert acknowledgement.body == "accepted"
        assert acknowledgement.reply_to == received[0].message_id

    asyncio.run(scenario())


def test_listener_rejects_untrusted_sender(tmp_path):
    async def scenario():
        alice = Identity.create("Alice")
        bob = Identity.create("Bob")
        server = PeerServer(bob, [], Database(tmp_path / "bob.db"))
        await server.start("127.0.0.1", 0)
        try:
            bob_card = bob.peer_card(f"127.0.0.1:{server.port}")
            with pytest.raises(DeliveryRejected, match="rejected"):
                await send_message(alice, bob_card, "not trusted")
        finally:
            await server.close()

    asyncio.run(scenario())


def test_listener_rejects_sender_over_the_rate_limit(tmp_path):
    async def scenario():
        alice = Identity.create("Alice")
        bob = Identity.create("Bob")
        alice_card = alice.peer_card("127.0.0.1:9001")
        server = PeerServer(
            bob,
            [alice_card],
            Database(tmp_path / "bob.db"),
            rate_limit_messages=2,
            rate_limit_window_seconds=60.0,
        )
        await server.start("127.0.0.1", 0)
        try:
            bob_card = bob.peer_card(f"127.0.0.1:{server.port}")
            await send_message(alice, bob_card, "one")
            await send_message(alice, bob_card, "two")
            with pytest.raises(DeliveryRejected, match="rejected"):
                await send_message(alice, bob_card, "three")
        finally:
            await server.close()

    asyncio.run(scenario())


def test_listener_rejects_replayed_envelope(tmp_path):
    async def exchange_raw(port: int, payload: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await write_frame(writer, payload)
            return await read_frame(reader)
        finally:
            writer.close()
            await writer.wait_closed()

    async def scenario():
        alice = Identity.create("Alice")
        bob = Identity.create("Bob")
        alice_card = alice.peer_card("127.0.0.1:9001")
        server = PeerServer(bob, [alice_card], Database(tmp_path / "bob.db"))
        await server.start("127.0.0.1", 0)
        try:
            bob_card = bob.peer_card(f"127.0.0.1:{server.port}")
            payload = encrypt_message(alice, bob_card, "send once").to_json().encode("utf-8")
            first = await exchange_raw(server.port, payload)
            second = await exchange_raw(server.port, payload)
        finally:
            await server.close()

        assert json.loads(first).get("ciphertext")
        assert json.loads(second) == {"error": "rejected"}

    asyncio.run(scenario())
