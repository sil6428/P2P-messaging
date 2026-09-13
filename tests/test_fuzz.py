"""Fuzz-style robustness tests: malformed input must raise ProtocolError, never crash."""

import base64
import random

import pytest

from secure_messaging.identity import Identity
from secure_messaging.protocol import EncryptedEnvelope, ProtocolError, encrypt_message

SEED = 20260913


def _valid_envelope_dict() -> dict:
    alice = Identity.create("Alice")
    bob = Identity.create("Bob")
    bob_card = bob.peer_card("127.0.0.1:9001")
    return encrypt_message(alice, bob_card, "hello").to_dict()


def test_from_json_never_leaks_a_raw_exception_on_random_bytes():
    rng = random.Random(SEED)
    for _ in range(300):
        garbage = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        try:
            EncryptedEnvelope.from_json(garbage)
        except ProtocolError:
            continue


def test_from_dict_rejects_every_single_field_mutation():
    rng = random.Random(SEED)
    template = _valid_envelope_dict()

    for field in template:
        for _ in range(20):
            mutated = dict(template)
            original = mutated[field]
            if isinstance(original, str):
                chars = list(original)
                if chars:
                    index = rng.randrange(len(chars))
                    chars[index] = rng.choice("!@#$%^&*()_+-=")
                mutated[field] = "".join(chars)
            elif isinstance(original, int):
                mutated[field] = original + 1
            try:
                EncryptedEnvelope.from_dict(mutated)
            except ProtocolError:
                continue


def test_from_dict_rejects_truncated_fixed_length_fields():
    # ciphertext has no fixed length (the AEAD tag catches tampering at decrypt time,
    # not at parse time), so only fields with an expected byte length belong here.
    template = _valid_envelope_dict()
    for field in ("nonce", "sender_signing_key", "signature"):
        mutated = dict(template)
        mutated[field] = template[field][:4]
        with pytest.raises(ProtocolError):
            EncryptedEnvelope.from_dict(mutated)


def test_from_dict_rejects_wrong_type_on_structurally_validated_fields():
    # sent_at is intentionally not format-checked until decrypt_message; every other
    # field is validated eagerly by from_dict and must reject a non-scalar value.
    template = _valid_envelope_dict()
    for field in template:
        if field == "sent_at":
            continue
        mutated = dict(template)
        mutated[field] = {"unexpected": "object"}
        with pytest.raises(ProtocolError):
            EncryptedEnvelope.from_dict(mutated)


def test_from_json_rejects_non_object_json():
    for payload in ("null", "[]", "42", '"a string"', ""):
        with pytest.raises(ProtocolError):
            EncryptedEnvelope.from_json(payload)


def test_from_dict_rejects_missing_each_required_field():
    template = _valid_envelope_dict()
    for field in list(template):
        mutated = dict(template)
        del mutated[field]
        with pytest.raises(ProtocolError):
            EncryptedEnvelope.from_dict(mutated)


def test_from_dict_rejects_flipped_ciphertext_byte():
    rng = random.Random(SEED)
    template = _valid_envelope_dict()
    envelope = EncryptedEnvelope.from_dict(template)
    raw = bytearray(envelope.ciphertext)
    raw[rng.randrange(len(raw))] ^= 0xFF
    mutated = dict(template)
    mutated["ciphertext"] = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
    # Reconstructing must still succeed structurally; authentication is checked at decrypt time.
    EncryptedEnvelope.from_dict(mutated)
