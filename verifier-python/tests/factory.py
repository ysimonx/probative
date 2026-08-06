"""Fabrique d'enveloppes — simulation d'un appareil côté test.

Ce module produit des enveloppes cryptographiquement valides sans aucun
matériel. Il joue le rôle que tiendra le code natif Kotlin et Swift, et
constitue de fait la référence d'implémentation : si le client Android
ou iOS produit une enveloppe que cette fabrique ne saurait pas produire,
c'est le client qui s'écarte de la spécification.

Attention : la clé est ici une clé logicielle. Sur appareil, elle est
générée dans le Keystore ou la Secure Enclave et n'est jamais exportable.
"""

from __future__ import annotations

import hashlib
import os
import time

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

SPEC = "ac/0.1"
DEPLOYMENT = "test-deployment"


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def kid_for(key: ec.EllipticCurvePrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    raw = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return hashlib.sha256(raw).digest()


def make_payload(
    *,
    nonce: bytes,
    platform: str = "android",
    media_digest: bytes | None = None,
    lat: float = 48.2973,
    lon: float = 4.0744,
    h_accuracy: float = 8.0,
    altitude: float | None = 112.0,
    baro_altitude: float | None = 115.0,
    provider: str = "gnss",
    fix_age_ms: int = 1_200,
    sign_latency_ms: int = 85,
    wall_ms: int | None = None,
    mock_location: bool | None = False,
    debugger: bool = False,
    emulator: bool = False,
    with_motion: bool = True,
    prev_digest: bytes | None = None,
    extra_claims: list[dict] | None = None,
) -> dict:
    media_digest = media_digest or hashlib.sha256(b"image-de-test").digest()
    wall_ms = wall_ms if wall_ms is not None else int(time.time() * 1000)

    claims: list[dict] = []
    if baro_altitude is not None:
        claims.append({1: "baro-alt", 2: "barometer", 3: 4_210, 4: baro_altitude})
        claims.append({1: "baro", 2: "barometer", 3: 4_210, 4: 999.4})
    if with_motion:
        claims.append(
            {
                1: "motion",
                2: "accelerometer",
                3: 4_100,
                4: [[0, 0.01, 0.02, 9.79], [500, 0.03, 0.01, 9.81]],
            }
        )
        claims.append({1: "steps", 2: "pedometer", 3: 4_180, 4: 0})
    if extra_claims:
        claims.extend(extra_claims)

    posture: dict = {
        1: platform,
        2: "14" if platform == "android" else "17.4",
        3: "0.1.0",
        4: debugger,
        5: emulator,
    }
    if platform == "android":
        posture[6] = False
        posture[7] = mock_location
        posture[8] = []
    else:
        posture[9] = False

    position: dict = {
        1: lat,
        2: lon,
        3: h_accuracy,
        6: provider,
        7: fix_age_ms,
    }
    if altitude is not None:
        position[4] = altitude
        position[5] = 4.0
    if platform == "android":
        position[8] = 11

    payload: dict = {
        1: nonce,
        2: {
            1: "sha-256",
            2: media_digest,
            3: "image/jpeg",
            4: 1_842_301,
            5: [4032, 3024],
            6: sign_latency_ms,
        },
        3: position,
        4: {1: wall_ms, 2: 4_312_004, 3: 120, 4: True},
        5: posture,
        6: claims,
    }
    if prev_digest is not None:
        payload[7] = prev_digest
    return payload


def sign_envelope(
    key: ec.EllipticCurvePrivateKey,
    payload: dict,
    *,
    nonce: bytes,
    counter: int | None = None,
    freshness_kind: str = "play-integrity",
    bind_challenge: bool = True,
    tamper_payload_after_sign: dict | None = None,
) -> bytes:
    """Assemble et signe une enveloppe COSE_Sign1.

    `bind_challenge=False` produit une enveloppe dont le jeton de
    fraîcheur ne couvre pas la charge utile : c'est l'attaque que la
    règle R1 doit intercepter.
    """
    protected = {
        1: -7,
        4: kid_for(key),
        100: SPEC,
        101: DEPLOYMENT,
    }
    protected_bytes = cbor2.dumps(protected, canonical=True)
    payload_bytes = cbor2.dumps(payload, canonical=True)

    challenge = hashlib.sha256(payload_bytes + nonce).digest()
    token = b"NULLTOKEN:" + (challenge if bind_challenge else os.urandom(32))

    freshness: dict = {1: freshness_kind, 2: token}
    if counter is not None:
        freshness[3] = counter

    sig_structure = cbor2.dumps(
        ["Signature1", protected_bytes, b"", payload_bytes]
    )
    der = key.sign(sig_structure, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    if tamper_payload_after_sign is not None:
        payload_bytes = cbor2.dumps(tamper_payload_after_sign, canonical=True)

    return cbor2.dumps(
        cbor2.CBORTag(18, [protected_bytes, {200: freshness}, payload_bytes, signature]),
        canonical=True,
    )
