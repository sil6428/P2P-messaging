from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

MAX_FILENAME_LENGTH = 255
_READ_CHUNK_BYTES = 1024 * 1024


class AttachmentError(ValueError):
    """Raised when an attachment reference cannot be built or parsed safely."""


class AttachmentStatus(str, Enum):
    """Outcome of comparing a received file against the digest bound in its message."""

    VERIFIED = "verified"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class AttachmentReference:
    """A digest binding for a file exchanged out-of-band, e.g. by the separate
    secure-file-transfer project. Only the filename, size, and digest travel inside a
    signed, encrypted message; file bytes are never sent over this protocol.
    """

    filename: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, str | int]:
        return {"filename": self.filename, "size_bytes": self.size_bytes, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AttachmentReference:
        try:
            filename = str(value["filename"])
            size_bytes = int(value["size_bytes"])
            sha256 = str(value["sha256"]).lower()
        except (KeyError, TypeError, ValueError) as exc:
            raise AttachmentError("Attachment reference is missing required fields.") from exc
        if not 1 <= len(filename) <= MAX_FILENAME_LENGTH or "/" in filename or "\\" in filename:
            raise AttachmentError("Attachment filename is invalid.")
        if size_bytes < 0:
            raise AttachmentError("Attachment size cannot be negative.")
        if len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256):
            raise AttachmentError("Attachment digest must be a 64-character hex SHA-256 value.")
        return cls(filename=filename, size_bytes=size_bytes, sha256=sha256)


def bind_attachment(path: str | Path) -> AttachmentReference:
    """Digest a local file so a reference to it can be embedded in a message without
    transmitting the file itself."""
    file_path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    return AttachmentReference(filename=file_path.name, size_bytes=size, sha256=digest.hexdigest())


def verify_attachment(reference: AttachmentReference, path: str | Path) -> AttachmentStatus:
    """Recompute a received file's digest and compare it against the reference bound in
    its message. Any read failure or mismatch must quarantine the file rather than trust it."""
    try:
        actual = bind_attachment(path)
    except OSError:
        return AttachmentStatus.QUARANTINED
    if actual.sha256 != reference.sha256 or actual.size_bytes != reference.size_bytes:
        return AttachmentStatus.INTEGRITY_MISMATCH
    return AttachmentStatus.VERIFIED
