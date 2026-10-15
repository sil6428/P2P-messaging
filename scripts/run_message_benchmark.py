from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from secure_messaging.database import Database
from secure_messaging.identity import Identity
from secure_messaging.protocol import EncryptedEnvelope, decrypt_message, encrypt_message
from secure_messaging.transport import PeerServer, read_frame, write_frame

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_PATH = ROOT / "results" / "message-replay-benchmark.json"


async def exchange_raw(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await write_frame(writer, payload)
        return await read_frame(reader)
    finally:
        writer.close()
        await writer.wait_closed()


async def bounded_map(payloads: list[bytes], workers: int, operation) -> list[object]:
    semaphore = asyncio.Semaphore(workers)

    async def run_one(index: int, payload: bytes) -> object:
        async with semaphore:
            return await operation(index, payload)

    return await asyncio.gather(
        *(run_one(index, payload) for index, payload in enumerate(payloads))
    )


async def run(*, message_count: int, workers: int) -> dict[str, object]:
    if message_count <= 0 or workers <= 0:
        raise ValueError("message count and workers must be positive")

    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="secure-messaging-benchmark-") as temporary:
        database = Database(Path(temporary) / "bob.db")
        alice = Identity.create("Alice")
        bob = Identity.create("Bob")
        alice_card = alice.peer_card("127.0.0.1:9001")
        server = PeerServer(
            bob,
            [alice_card],
            database,
            rate_limit_messages=(message_count * 2) + workers,
            rate_limit_window_seconds=3600.0,
        )
        await server.start("127.0.0.1", 0)
        bob_card = bob.peer_card(f"127.0.0.1:{server.port}")
        envelopes = [
            encrypt_message(alice, bob_card, f"benchmark-message-{index:05d}")
            for index in range(message_count)
        ]
        payloads = [envelope.to_json().encode("utf-8") for envelope in envelopes]

        try:
            delivery_started = time.perf_counter()

            async def deliver(index: int, payload: bytes) -> bool:
                response = await exchange_raw(server.port, payload)
                acknowledgement = EncryptedEnvelope.from_json(response)
                message = decrypt_message(alice, bob_card, acknowledgement)
                return (
                    message.kind == "ack"
                    and message.body == "accepted"
                    and message.reply_to == envelopes[index].message_id
                )

            delivery_results = await bounded_map(payloads, workers, deliver)
            delivery_seconds = time.perf_counter() - delivery_started

            replay_started = time.perf_counter()

            async def replay(_: int, payload: bytes) -> bool:
                response = await exchange_raw(server.port, payload)
                try:
                    decoded = json.loads(response)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return False
                return decoded == {"error": "rejected"}

            replay_results = await bounded_map(payloads, workers, replay)
            replay_seconds = time.perf_counter() - replay_started
        finally:
            await server.close()

        accepted_messages = sum(result is True for result in delivery_results)
        rejected_replays = sum(result is True for result in replay_results)
        persisted_message_ids = database.received_message_count()
        return {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "protocol": (
                "loopback TCP with Ed25519 signatures, X25519 key agreement, "
                "ChaCha20-Poly1305 authenticated encryption, authenticated acknowledgements, "
                "and SQLite-backed replay rejection"
            ),
            "message_count": message_count,
            "worker_count": workers,
            "authenticated_messages_accepted": accepted_messages,
            "authenticated_acknowledgements_verified": accepted_messages,
            "replay_attempts": message_count,
            "replay_attempts_rejected": rejected_replays,
            "persisted_unique_message_ids": persisted_message_ids,
            "validated_protocol_operations": accepted_messages + rejected_replays,
            "delivery_duration_seconds": round(delivery_seconds, 4),
            "replay_duration_seconds": round(replay_seconds, 4),
            "duration_seconds": round(time.perf_counter() - started, 4),
            "all_verified": (
                accepted_messages == message_count
                and rejected_replays == message_count
                and persisted_message_ids == message_count
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark authenticated loopback delivery and persistent replay rejection"
    )
    parser.add_argument("--messages", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT_PATH)
    args = parser.parse_args()

    result = asyncio.run(run(message_count=args.messages, workers=args.workers))
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
