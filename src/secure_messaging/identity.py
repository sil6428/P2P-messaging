from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256, Hash

IDENTITY_VERSION = 1
MIN_PASSWORD_LENGTH = 12


class IdentityError(ValueError):
    """Raised when identity or peer-card data cannot be trusted."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str, *, expected_length: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise IdentityError("Invalid base64 identity value.") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise IdentityError("Identity key has an unexpected length.")
    return decoded


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_endpoint(endpoint: str) -> tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        closing = endpoint.find("]:")
        if closing < 0:
            raise IdentityError("IPv6 endpoints must use [address]:port.")
        host, port_text = endpoint[1:closing], endpoint[closing + 2 :]
    else:
        try:
            host, port_text = endpoint.rsplit(":", 1)
        except ValueError as exc:
            raise IdentityError("Endpoint must use host:port.") from exc

    if not host or any(character.isspace() for character in host):
        raise IdentityError("Endpoint host is invalid.")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise IdentityError("Endpoint port must be a number.") from exc
    if not 1 <= port <= 65535:
        raise IdentityError("Endpoint port must be between 1 and 65535.")
    return host, port


@dataclass(frozen=True, slots=True)
class PeerCard:
    display_name: str
    endpoint: str
    signing_key: bytes
    encryption_key: bytes
    signature: bytes
    version: int = IDENTITY_VERSION

    def _unsigned_payload(self) -> dict[str, str | int]:
        return {
            "display_name": self.display_name,
            "encryption_key": _b64encode(self.encryption_key),
            "endpoint": self.endpoint,
            "signing_key": _b64encode(self.signing_key),
            "version": self.version,
        }

    def verify(self) -> None:
        if self.version != IDENTITY_VERSION:
            raise IdentityError("Unsupported peer-card version.")
        if not 1 <= len(self.display_name.strip()) <= 80:
            raise IdentityError("Display name must contain 1 to 80 characters.")
        parse_endpoint(self.endpoint)
        if len(self.signing_key) != 32 or len(self.encryption_key) != 32:
            raise IdentityError("Peer card contains an invalid public key.")
        try:
            Ed25519PublicKey.from_public_bytes(self.signing_key).verify(
                self.signature,
                _canonical_json(self._unsigned_payload()),
            )
        except (InvalidSignature, ValueError) as exc:
            raise IdentityError("Peer-card signature is invalid.") from exc

    @property
    def fingerprint(self) -> str:
        digest = Hash(SHA256())
        digest.update(self.signing_key)
        hex_digest = digest.finalize().hex().upper()
        return " ".join(hex_digest[index : index + 4] for index in range(0, 64, 4))

    def to_dict(self) -> dict[str, str | int]:
        return {**self._unsigned_payload(), "signature": _b64encode(self.signature)}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PeerCard:
        try:
            card = cls(
                display_name=str(value["display_name"]),
                endpoint=str(value["endpoint"]),
                signing_key=_b64decode(str(value["signing_key"]), expected_length=32),
                encryption_key=_b64decode(str(value["encryption_key"]), expected_length=32),
                signature=_b64decode(str(value["signature"]), expected_length=64),
                version=int(value["version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityError("Peer card is missing required fields.") from exc
        card.verify()
        return card

    @classmethod
    def from_json(cls, value: str) -> PeerCard:
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise IdentityError("Peer card is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise IdentityError("Peer card must be a JSON object.")
        return cls.from_dict(payload)

    @classmethod
    def load(cls, path: str | Path) -> PeerCard:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.to_json() + "\n", encoding="utf-8")


@dataclass(slots=True)
class Identity:
    display_name: str
    signing_private_key: Ed25519PrivateKey
    encryption_private_key: X25519PrivateKey

    @classmethod
    def create(cls, display_name: str) -> Identity:
        clean_name = display_name.strip()
        if not 1 <= len(clean_name) <= 80:
            raise IdentityError("Display name must contain 1 to 80 characters.")
        return cls(clean_name, Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @property
    def signing_public_key(self) -> bytes:
        return self.signing_private_key.public_key().public_bytes_raw()

    @property
    def encryption_public_key(self) -> bytes:
        return self.encryption_private_key.public_key().public_bytes_raw()

    def peer_card(self, endpoint: str) -> PeerCard:
        parse_endpoint(endpoint)
        unsigned = {
            "display_name": self.display_name,
            "encryption_key": _b64encode(self.encryption_public_key),
            "endpoint": endpoint,
            "signing_key": _b64encode(self.signing_public_key),
            "version": IDENTITY_VERSION,
        }
        return PeerCard(
            display_name=self.display_name,
            endpoint=endpoint,
            signing_key=self.signing_public_key,
            encryption_key=self.encryption_public_key,
            signature=self.signing_private_key.sign(_canonical_json(unsigned)),
        )

    def save(self, path: str | Path, password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise IdentityError(f"Identity password must be at least {MIN_PASSWORD_LENGTH} characters.")
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        payload = {
            "display_name": self.display_name,
            "encryption_private_key": _b64encode(
                self.encryption_private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    encryption,
                )
            ),
            "signing_private_key": _b64encode(
                self.signing_private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    encryption,
                )
            ),
            "version": IDENTITY_VERSION,
        }
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: str | Path, password: str) -> Identity:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            if payload["version"] != IDENTITY_VERSION:
                raise IdentityError("Unsupported identity-file version.")
            signing_key = serialization.load_pem_private_key(
                _b64decode(payload["signing_private_key"]),
                password=password.encode("utf-8"),
            )
            encryption_key = serialization.load_pem_private_key(
                _b64decode(payload["encryption_private_key"]),
                password=password.encode("utf-8"),
            )
        except IdentityError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityError("Identity file or password is invalid.") from exc
        if not isinstance(signing_key, Ed25519PrivateKey) or not isinstance(
            encryption_key, X25519PrivateKey
        ):
            raise IdentityError("Identity file contains unexpected key types.")
        return cls(str(payload["display_name"]), signing_key, encryption_key)
