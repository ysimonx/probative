"""Vecteurs d'or — octets de référence pour les encodeurs natifs.

Les cœurs Kotlin et Swift doivent produire, pour les mêmes entrées,
exactement les octets figés ici : c'est le test de canonicité CBOR
(spec §7) le moins cher et le plus discriminant. Quatre jeux couvrent les
formes de charge utile : `android` (profil capture, chaînage, posture
7/8), `ios` (profil capture, compteur d'assertion, posture 9), `core`
(profil noyau, forme Android) et `core-ios` (profil noyau, forme iOS).

Le jeu `core` n'est pas décoratif : c'est la seule forme qui puisse
atteindre `STRONG`, et donc la seule qui vérifie que le plafond de
recapture est bien attaché au profil `capture` et non au format.

Le noyau existe en **deux** formes parce que `posture` diffère d'une
plateforme à l'autre, et c'est le seul bloc qui le fasse. Un seul jeu
laissait le cœur de l'autre plateforme sans oracle pour le profil noyau —
un trou d'autant plus fâcheux que le noyau est le profil qu'un
intégrateur atteint sans caméra.

Toutes les entrées sont déterministes, y compris la clé — une clé
*logicielle de test*, dérivée d'une étiquette publique. Ce n'est pas du
matériel cryptographique réel au sens du `.gitignore` : elle ne protège
rien et n'existe sur aucun appareil.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from factory import (
    PROFILE_CAPTURE,
    PROFILE_CORE,
    encode_protected,
    encode_sig_structure,
    kid_for,
    make_payload,
    sign_envelope,
)

VECTORS_DIR = Path(__file__).parent / "vectors"

# nom du jeu → (plateforme, profil). Le nom sert d'étiquette de dérivation
# des clés et de nonces : il ne doit jamais changer sans régénération.
VECTOR_SETS: dict[str, tuple[str, str]] = {
    "android": ("android", PROFILE_CAPTURE),
    "ios": ("ios", PROFILE_CAPTURE),
    "core": ("android", PROFILE_CORE),
    # Le noyau existe en deux formes, parce que `posture` diffère : labels
    # 6/7/8 côté Android, label 9 côté iOS. Sans ce quatrième jeu, le cœur
    # Swift n'avait **aucun oracle** pour le profil noyau — il ne pouvait pas
    # reproduire `core`, de forme Android, et rien d'autre ne l'épinglait.
    # C'est précisément le trou qu'un vecteur existe pour fermer.
    "core-ios": ("ios", PROFILE_CORE),
}

# Ordre du groupe P-256 : borne de dérivation de la clé de test.
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Horloge murale figée pour la reproductibilité ; la valeur est arbitraire.
WALL_MS = 1_754_400_000_000


def vector_key(name: str) -> ec.EllipticCurvePrivateKey:
    """Clé P-256 de test, dérivée d'une étiquette. Jamais sur un appareil."""
    d = int.from_bytes(_digest(f"probative/0.1 vecteur cle {name}"), "big")
    return ec.derive_private_key(d % (_P256_ORDER - 1) + 1, ec.SECP256R1())


def vector_nonce(name: str) -> bytes:
    return _digest(f"probative/0.1 vecteur nonce {name}")[:16]


def vector_prev_digest() -> bytes:
    """Condensat de l'enveloppe précédente, pour le chaînage Android."""
    return _digest("probative/0.1 vecteur enveloppe precedente")


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


# Le média des vecteurs est ce texte : son empreinte figure dans la
# charge utile, et les tests de vérification le fournissent tel quel.
MEDIA = b"probative/0.1 vecteur media"


def build_vectors() -> dict[str, bytes]:
    """Construit tous les fichiers de vecteurs, nom → contenu exact."""
    files: dict[str, bytes] = {}
    manifest: dict[str, Any] = {}

    for name, (platform, profile) in VECTOR_SETS.items():
        key = vector_key(name)
        nonce = vector_nonce(name)
        prev_digest = vector_prev_digest() if platform == "android" else None
        counter = 7 if platform == "ios" else None
        freshness_kind = "play-integrity" if platform == "android" else "app-attest"

        payload = make_payload(
            nonce=nonce,
            profile=profile,
            platform=platform,
            media_digest=hashlib.sha256(MEDIA).digest(),
            wall_ms=WALL_MS,
            prev_digest=prev_digest,
        )
        payload_bytes = cbor2.dumps(payload, canonical=True)
        protected_bytes = encode_protected(key, profile)
        sig_structure = encode_sig_structure(protected_bytes, payload_bytes)
        challenge = hashlib.sha256(payload_bytes + nonce).digest()
        envelope = sign_envelope(
            key,
            payload,
            nonce=nonce,
            profile=profile,
            counter=counter,
            freshness_kind=freshness_kind,
            deterministic_signature=True,
        )

        files[f"{name}.payload.cbor"] = payload_bytes
        files[f"{name}.protected.cbor"] = protected_bytes
        files[f"{name}.sig_structure.cbor"] = sig_structure
        files[f"{name}.challenge.bin"] = challenge
        files[f"{name}.envelope.prbv"] = envelope

        public_x962 = key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        manifest[name] = {
            "private_key_d_hex": format(key.private_numbers().private_value, "064x"),
            "public_key_x962_hex": public_x962.hex(),
            "kid_hex": kid_for(key).hex(),
            "nonce_hex": nonce.hex(),
            "platform": platform,
            "profile": profile,
            "media_hex": MEDIA.hex(),
            "media_digest_hex": hashlib.sha256(MEDIA).hexdigest(),
            "prev_digest_hex": prev_digest.hex() if prev_digest else None,
            "assertion_counter": counter,
            "freshness_kind": freshness_kind,
            "wall_ms": WALL_MS,
        }

    files["manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    return files


def write_vectors(directory: Path = VECTORS_DIR) -> list[str]:
    """Écrit les vecteurs sur disque, retourne les noms écrits."""
    directory.mkdir(parents=True, exist_ok=True)
    files = build_vectors()
    for name, content in files.items():
        (directory / name).write_bytes(content)
    return sorted(files)
