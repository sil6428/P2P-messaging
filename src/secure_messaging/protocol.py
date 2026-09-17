from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_messaging.attachments import AttachmentError, AttachmentReference
from secure_messaging.identity import Identity, PeerCard

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 4096
DEFAULT_MAX_AGE = timedelta(days=7)
MAX_CLOCK_SKEW = timedelta(minutes=5)


class ProtocolError(ValueError):
    """Raised when a message envelope is invalid or cannot be authenticated."""


class AuthenticationError(ProtocolError):
    """Raised when an envelope fails a sender, recipient, signature, or AEAD check."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str, *, expected_length: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("Envelope contains invalid base64.") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ProtocolError("Envelope value has an unexpected length.")
    return decoded


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_key(identity: Identity, peer: PeerCard, sender_key: bytes, recipient_key: bytes) -> bytes:
    shared_secret = identity.encryption_private_key.exchange(
        X25519PublicKey.from_public_bytes(peer.encryption_key)
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-messaging/v1/directional/" + sender_key + recipient_key,
    ).derive(shared_secret)


@dataclass(frozen=True, slots=True)
class EncryptedEnvelope:
    message_id: str
    sender_signing_key: bytes
    sender_encryption_key: bytes
    recipient_signing_key: bytes
    recipient_encryption_key: bytes
    sent_at: str
    nonce: bytes
    ciphertext: bytes
    signature: bytes
    version: int = PROTOCOL_VERSION

    def header(self) -> dict[str, str | int]:
        return {
            "message_id": self.message_id,
            "nonce": _b64encode(self.nonce),
            "recipient_encryption_key": _b64encode(self.recipient_encryption_key),
            "recipient_signing_key": _b64encode(self.recipient_signing_key),
            "sender_encryption_key": _b64encode(self.sender_encryption_key),
            "sender_signing_key": _b64encode(self.sender_signing_key),
            "sent_at": self.sent_at,
            "version": self.version,
        }

    def signed_bytes(self) -> bytes:
        return _canonical_json(self.header()) + self.ciphertext

    def to_dict(self) -> dict[str, str | int]:
        return {
            **self.header(),
            "ciphertext": _b64encode(self.ciphertext),
            "signature": _b64encode(self.signature),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EncryptedEnvelope:
        try:
            envelope = cls(
                message_id=str(value["message_id"]),
                sender_signing_key=_b64decode(
                    str(value["sender_signing_key"]), expected_length=32
                ),
                sender_encryption_key=_b64decode(
                    str(value["sender_encryption_key"]), expected_length=32
                ),
                recipient_signing_key=_b64decode(
                    str(value["recipient_signing_key"]), expected_length=32
                ),
                recipient_encryption_key=_b64decode(
                    str(value["recipient_encryption_key"]), expected_length=32
                ),
                sent_at=str(value["sent_at"]),
                nonce=_b64decode(str(value["nonce"]), expected_length=12),
                ciphertext=_b64decode(str(value["ciphertext"])),
                signature=_b64decode(str(value["signature"]), expected_length=64),
                version=int(value["version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("Envelope is missing required fields.") from exc
        if envelope.version != PROTOCOL_VERSION:
            raise ProtocolError("Unsupported protocol version.")
        try:
            uuid.UUID(hex=envelope.message_id)
        except ValueError as exc:
            raise ProtocolError("Message identifier is invalid.") from exc
        if len(envelope.ciphertext) > MAX_MESSAGE_BYTES + 1024:
            raise ProtocolError("Encrypted message is too large.")
        return envelope

    @classmethod
    def from_json(cls, value: str | bytes) -> EncryptedEnvelope:
        try:
            payload = json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ProtocolError("Envelope is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ProtocolError("Envelope must be a JSON object.")
        return cls.from_dict(payload)


@dataclass(frozen=True, slots=True)
class DecryptedMessage:
    message_id: str
    sender_name: str
    sent_at: datetime
    kind: Literal["message", "ack"]
    body: str
    reply_to: str | None
    sender_signing_key: bytes
    attachment: AttachmentReference | None = None


def encrypt_message(
    sender: Identity,
    recipient: PeerCard,
    body: str,
    *,
    kind: Literal["message", "ack"] = "message",
    reply_to: str | None = None,
    sent_at: datetime | None = None,
    attachment: AttachmentReference | None = None,
) -> EncryptedEnvelope:
    recipient.verify()
    body_bytes = body.encode("utf-8")
    if not body_bytes or len(body_bytes) > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"Message must contain 1 to {MAX_MESSAGE_BYTES} UTF-8 bytes.")
    if kind not in {"message", "ack"}:
        raise ProtocolError("Unsupported message kind.")
    if kind == "ack" and not reply_to:
        raise ProtocolError("Acknowledgements must reference a message.")
    if attachment is not None and kind != "message":
        raise ProtocolError("Only direct messages may carry an attachment reference.")

    timestamp = (sent_at or datetime.now(UTC)).astimezone(UTC)
    envelope = EncryptedEnvelope(
        message_id=uuid.uuid4().hex,
        sender_signing_key=sender.signing_public_key,
        sender_encryption_key=sender.encryption_public_key,
        recipient_signing_key=recipient.signing_key,
        recipient_encryption_key=recipient.encryption_key,
        sent_at=timestamp.isoformat(timespec="seconds").replace("+00:00", "Z"),
        nonce=os.urandom(12),
        ciphertext=b"",
        signature=b"",
    )
    plaintext = _canonical_json(
        {
            "body": body,
            "kind": kind,
            "reply_to": reply_to,
            "attachment": attachment.to_dict() if attachment is not None else None,
        }
    )
    key = _derive_key(
        sender,
        recipient,
        envelope.sender_signing_key,
        envelope.recipient_signing_key,
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(
        envelope.nonce,
        plaintext,
        _canonical_json(envelope.header()),
    )
    envelope = replace(envelope, ciphertext=ciphertext)
    signature = sender.signing_private_key.sign(envelope.signed_bytes())
    return replace(envelope, signature=signature)


def decrypt_message(
    recipient: Identity,
    sender: PeerCard,
    envelope: EncryptedEnvelope,
    *,
    now: datetime | None = None,
    max_age: timedelta = DEFAULT_MAX_AGE,
) -> DecryptedMessage:
    sender.verify()
    if envelope.sender_signing_key != sender.signing_key or (
        envelope.sender_encryption_key != sender.encryption_key
    ):
        raise AuthenticationError("Envelope does not match the trusted sender.")
    if envelope.recipient_signing_key != recipient.signing_public_key or (
        envelope.recipient_encryption_key != recipient.encryption_public_key
    ):
        raise AuthenticationError("Envelope was intended for another recipient.")
    try:
        Ed25519PublicKey.from_public_bytes(sender.signing_key).verify(
            envelope.signature,
            envelope.signed_bytes(),
        )
    except InvalidSignature as exc:
        raise AuthenticationError("Envelope signature is invalid.") from exc

    try:
        sent_at = datetime.fromisoformat(envelope.sent_at)
    except ValueError as exc:
        raise ProtocolError("Envelope timestamp is invalid.") from exc
    if sent_at.tzinfo is None:
        raise ProtocolError("Envelope timestamp must include a timezone.")
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    sent_at = sent_at.astimezone(UTC)
    if sent_at > current_time + MAX_CLOCK_SKEW:
        raise ProtocolError("Envelope timestamp is too far in the future.")
    if current_time - sent_at > max_age:
        raise ProtocolError("Envelope has expired.")

    key = _derive_key(
        recipient,
        sender,
        envelope.sender_signing_key,
        envelope.recipient_signing_key,
    )
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            envelope.nonce,
            envelope.ciphertext,
            _canonical_json(envelope.header()),
        )
    except InvalidTag as exc:
        raise AuthenticationError("Encrypted message authentication failed.") from exc
    try:
        payload = json.loads(plaintext)
        kind = payload["kind"]
        body = payload["body"]
        reply_to = payload["reply_to"]
        raw_attachment = payload.get("attachment")
    except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise ProtocolError("Decrypted message has an invalid structure.") from exc
    if kind not in {"message", "ack"} or not isinstance(body, str):
        raise ProtocolError("Decrypted message fields are invalid.")
    if not body.encode("utf-8") or len(body.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ProtocolError("Decrypted message has an invalid size.")
    if reply_to is not None and not isinstance(reply_to, str):
        raise ProtocolError("Reply reference is invalid.")
    attachment: AttachmentReference | None = None
    if raw_attachment is not None:
        if kind != "message" or not isinstance(raw_attachment, dict):
            raise ProtocolError("Attachment reference is invalid.")
        try:
            attachment = AttachmentReference.from_dict(raw_attachment)
        except AttachmentError as exc:
            raise ProtocolError("Attachment reference is invalid.") from exc
    return DecryptedMessage(
        message_id=envelope.message_id,
        sender_name=sender.display_name,
        sent_at=sent_at,
        kind=kind,
        body=body,
        reply_to=reply_to,
        sender_signing_key=envelope.sender_signing_key,
        attachment=attachment,
    )
