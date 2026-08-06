"""Vecteurs d'or : anti-dérive et validité.

Deux garanties. D'abord, les fichiers versionnés correspondent octet à
octet à une régénération : toute dérive de la fabrique ou de cbor2
casse ce test — jamais silencieusement les cœurs natifs qui se calent
sur ces octets. Ensuite, les enveloppes des vecteurs sont réellement
acceptées par le pipeline : des vecteurs stables mais invalides
feraient viser une mauvaise cible aux implémentations natives.
"""

from __future__ import annotations

from factory import kid_for
from vectors import MEDIA, VECTORS_DIR, WALL_MS, build_vectors, vector_key, vector_nonce

from attested_capture.attestation import DeviceIntegrity, NullAttestationVerifier
from attested_capture.model import Level, VerificationResult
from attested_capture.store import (
    DeviceRecord,
    InMemoryDeviceStore,
    InMemoryNonceStore,
)
from attested_capture.verifier import Verifier

REGEN = "relancer tools/gen_vectors.py et examiner le diff avant de committer"


def test_vecteurs_identiques_a_une_regeneration():
    files = build_vectors()
    # Les fichiers cachés (`.DS_Store`…) ne sont pas des vecteurs.
    on_disk = {
        p.name
        for p in VECTORS_DIR.iterdir()
        if p.name != "README.md" and not p.name.startswith(".")
    }
    assert on_disk == set(files), f"fichiers en trop ou manquants — {REGEN}"
    for name, content in files.items():
        assert (VECTORS_DIR / name).read_bytes() == content, f"dérive sur {name} — {REGEN}"


def _verify_vector(platform: str) -> VerificationResult:
    key = vector_key(platform)
    nonces = InMemoryNonceStore()
    # L'horloge des vecteurs est figée : le nonce est réputé émis juste
    # avant la capture, et la vérification datée juste après.
    nonces.issue(vector_nonce(platform)).issued_at_ms = WALL_MS - 1_000
    devices = InMemoryDeviceStore()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(key),
            public_key=key.public_key(),
            platform=platform,
            hardware_backed=True,
        )
    )
    verifier = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.STRONG),
    )
    envelope = (VECTORS_DIR / f"{platform}.envelope.acap").read_bytes()
    return verifier.verify(envelope, media_bytes=MEDIA, now_ms=WALL_MS + 2_000)


def test_enveloppe_vecteur_android_acceptee():
    res = _verify_vector("android")
    assert res.level in (Level.STANDARD, Level.STRONG), res.to_dict()


def test_enveloppe_vecteur_ios_acceptee():
    res = _verify_vector("ios")
    assert res.level in (Level.STANDARD, Level.STRONG), res.to_dict()
