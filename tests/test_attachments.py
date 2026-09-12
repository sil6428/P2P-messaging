import pytest

from secure_messaging.attachments import (
    AttachmentError,
    AttachmentReference,
    AttachmentStatus,
    bind_attachment,
    verify_attachment,
)


def test_bind_attachment_computes_digest_and_size(tmp_path):
    path = tmp_path / "file.txt"
    path.write_bytes(b"hello world")

    reference = bind_attachment(path)

    assert reference.filename == "file.txt"
    assert reference.size_bytes == 11
    assert len(reference.sha256) == 64


def test_verify_attachment_accepts_matching_file(tmp_path):
    path = tmp_path / "file.txt"
    path.write_bytes(b"hello world")
    reference = bind_attachment(path)

    assert verify_attachment(reference, path) == AttachmentStatus.VERIFIED


def test_verify_attachment_flags_tampered_file(tmp_path):
    path = tmp_path / "file.txt"
    path.write_bytes(b"hello world")
    reference = bind_attachment(path)
    path.write_bytes(b"hello world, tampered")

    assert verify_attachment(reference, path) == AttachmentStatus.INTEGRITY_MISMATCH


def test_verify_attachment_quarantines_missing_file(tmp_path):
    reference = AttachmentReference(filename="missing.txt", size_bytes=0, sha256="0" * 64)

    assert verify_attachment(reference, tmp_path / "missing.txt") == AttachmentStatus.QUARANTINED


def test_reference_round_trips_through_dict():
    reference = AttachmentReference(filename="file.txt", size_bytes=3, sha256="a" * 64)

    assert AttachmentReference.from_dict(reference.to_dict()) == reference


@pytest.mark.parametrize(
    "value",
    [
        {"filename": "../etc/passwd", "size_bytes": 1, "sha256": "a" * 64},
        {"filename": "a/b", "size_bytes": 1, "sha256": "a" * 64},
        {"filename": "file.txt", "size_bytes": -1, "sha256": "a" * 64},
        {"filename": "file.txt", "size_bytes": 1, "sha256": "not-hex"},
        {"filename": "file.txt", "size_bytes": 1, "sha256": "a" * 63},
        {"filename": "", "size_bytes": 1, "sha256": "a" * 64},
    ],
)
def test_reference_rejects_invalid_fields(value):
    with pytest.raises(AttachmentError):
        AttachmentReference.from_dict(value)
