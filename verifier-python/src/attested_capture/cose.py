"""COSE_Sign1 (RFC 8152) réduit au strict nécessaire : ES256 uniquement.

On n'utilise volontairement pas de bibliothèque COSE généraliste. La
surface acceptée doit rester minimale : un seul algorithme, une seule
structure. Tout ce qui n'est pas explicitement prévu est rejeté.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from .errors import InvalidSignature, MalformedEnvelope

COSE_SIGN1_TAG = 18
ALG_ES256 = -7

HDR_ALG = 1
HDR_KID = 4
HDR_SPEC = 100
HDR_DEPLOYMENT = 101
HDR_FRESHNESS = 200


@dataclass(frozen=True)
class Sign1:
    protected_bytes: bytes
    protected: Mapping
    unprotected: Mapping
    payload_bytes: bytes
    signature: bytes

    @property
    def spec(self) -> str:
        v = self.protected.get(HDR_SPEC)
        if not isinstance(v, str):
            raise MalformedEnvelope("version de spécification absente ou invalide")
        return v

    @property
    def kid(self) -> bytes:
        v = self.protected.get(HDR_KID)
        if not isinstance(v, bytes):
            raise MalformedEnvelope("kid absent ou invalide")
        return v

    @property
    def deployment(self) -> str | None:
        return self.protected.get(HDR_DEPLOYMENT)

    def payload(self) -> Any:
        return cbor2.loads(self.payload_bytes)


def decode(envelope: bytes) -> Sign1:
    """Décode une enveloppe étiquetée sans en vérifier la signature."""
    try:
        obj = cbor2.loads(envelope)
    except Exception as exc:  # noqa: BLE001 - entrée hostile
        raise MalformedEnvelope(f"CBOR illisible : {exc}") from exc

    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != COSE_SIGN1_TAG:
            raise MalformedEnvelope(f"étiquette CBOR inattendue : {obj.tag}")
        obj = obj.value

    # cbor2 en mode canonique restitue des types immuables (tuple,
    # frozendict). C'est une propriete souhaitable sur une entree
    # hostile : on teste donc les types abstraits, pas list/dict.
    if not isinstance(obj, Sequence) or isinstance(obj, (bytes, str)) or len(obj) != 4:
        raise MalformedEnvelope("structure COSE_Sign1 attendue : tableau de 4 éléments")

    protected_bytes, unprotected, payload_bytes, signature = obj

    if not isinstance(protected_bytes, bytes):
        raise MalformedEnvelope("en-tête protégé non sérialisé")
    if not isinstance(payload_bytes, bytes):
        raise MalformedEnvelope("charge utile détachée non supportée")
    if not isinstance(signature, bytes):
        raise MalformedEnvelope("signature absente")

    try:
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
    except Exception as exc:  # noqa: BLE001
        raise MalformedEnvelope(f"en-tête protégé illisible : {exc}") from exc

    if not isinstance(protected, Mapping):
        raise MalformedEnvelope("en-tête protégé : map attendue")
    if protected.get(HDR_ALG) != ALG_ES256:
        raise MalformedEnvelope("seul ES256 (-7) est accepté")

    return Sign1(
        protected_bytes=protected_bytes,
        protected=protected,
        unprotected=dict(unprotected) if isinstance(unprotected, Mapping) else {},
        payload_bytes=payload_bytes,
        signature=signature,
    )


def sig_structure(s: Sign1, external_aad: bytes = b"") -> bytes:
    """Structure `Sig_structure` de la RFC 8152, §4.4."""
    return cbor2.dumps(["Signature1", s.protected_bytes, external_aad, s.payload_bytes])


def verify_signature(s: Sign1, public_key: ec.EllipticCurvePublicKey) -> None:
    """Vérifie la signature ES256. La signature COSE est en format brut r||s."""
    if len(s.signature) != 64:
        raise InvalidSignature("longueur de signature ES256 invalide")

    r = int.from_bytes(s.signature[:32], "big")
    sv = int.from_bytes(s.signature[32:], "big")
    der = asym_utils.encode_dss_signature(r, sv)

    try:
        public_key.verify(der, sig_structure(s), ec.ECDSA(hashes.SHA256()))
    except _CryptoInvalidSignature as exc:
        raise InvalidSignature("la signature ne correspond pas à la clé enrôlée") from exc


def binding_challenge(payload_bytes: bytes, nonce: bytes) -> bytes:
    """Règle R1 — liaison de la fraîcheur au contenu.

    C'est la règle qui empêche d'associer un jeton d'attestation
    authentique à une charge utile forgée. Elle ne doit jamais être
    assouplie : sans elle, l'enveloppe atteste seulement qu'un appareil
    sain existe quelque part.
    """
    return hashlib.sha256(payload_bytes + nonce).digest()
