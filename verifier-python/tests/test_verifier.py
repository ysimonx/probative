"""Suite de vérification.

Les tests sont organisés en deux blocs : les cas nominaux, et les
scénarios d'attaque du modèle de menace. Chaque test d'attaque référence
la surface concernée (S1 à S4) pour que la traçabilité avec le document
reste vérifiable.
"""

from __future__ import annotations

import hashlib
import os
import time

import cbor2
import pytest

from attested_capture.attestation import DeviceIntegrity, NullAttestationVerifier
from attested_capture.model import Grade, Level, Property
from attested_capture.store import (
    DeviceRecord,
    InMemoryDeviceStore,
    InMemoryNonceStore,
)
from attested_capture.verifier import Verifier

from factory import kid_for, make_payload, new_key, sign_envelope

MEDIA = b"image-de-test"
MEDIA_DIGEST = hashlib.sha256(MEDIA).digest()


@pytest.fixture
def key():
    return new_key()


@pytest.fixture
def nonces():
    return InMemoryNonceStore()


@pytest.fixture
def devices(key):
    store = InMemoryDeviceStore()
    store.enroll(
        DeviceRecord(
            kid=kid_for(key),
            public_key=key.public_key(),
            platform="android",
            hardware_backed=True,
        )
    )
    return store


@pytest.fixture
def verifier(nonces, devices):
    return Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.STRONG),
    )


def _issue(nonces, **kw):
    nonce = os.urandom(16)
    nonces.issue(nonce, **kw)
    return nonce


# --- Cas nominaux -------------------------------------------------------


def test_capture_android_valide(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level in (Level.STANDARD, Level.STRONG)
    assert res.properties[Property.INTEGRITY].grade is Grade.A
    assert res.properties[Property.POSITION].grade is Grade.A
    assert "baro-consistent" in res.properties[Property.POSITION].evidence


def test_origin_plafonne_en_v01(verifier, nonces, key):
    """La photographie d'écran n'étant pas détectée, origin ne peut pas valoir A."""
    nonce = _issue(nonces)
    env = sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.ORIGIN].grade is Grade.B
    assert res.level is Level.STANDARD


def test_ios_compteur_assertion_donne_grade_a_sur_time(nonces, key):
    devices = InMemoryDeviceStore()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(key),
            public_key=key.public_key(),
            platform="ios",
            hardware_backed=True,
            assertion_counter=7,
        )
    )
    v = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.STRONG),
    )
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, platform="ios", media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, counter=8, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.TIME].grade is Grade.A
    assert "assertion-counter-monotonic" in res.properties[Property.TIME].evidence


def test_reclamation_inconnue_signalee_sans_penalite(verifier, nonces, key):
    """Extensibilité : un type inconnu est signalé, jamais pénalisant."""
    nonce = _issue(nonces)
    payload = make_payload(
        nonce=nonce,
        media_digest=MEDIA_DIGEST,
        extra_claims=[{1: "wifi-v2", 2: "scan", 3: 4_300, 4: ["abc", "def"]}],
    )
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert "UNKNOWN_CLAIMS" in res.flags
    assert res.level is Level.STANDARD


# --- S1 : falsification de position -------------------------------------


def test_s1_mock_location_declare(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, mock_location=True)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.UNTRUSTED
    assert res.properties[Property.POSITION].grade is Grade.F


def test_s1_incoherence_altimetrique(verifier, nonces, key):
    """Un GPS téléporté ne s'accompagne pas d'un baromètre cohérent."""
    nonce = _issue(nonces)
    payload = make_payload(
        nonce=nonce, media_digest=MEDIA_DIGEST, altitude=112.0, baro_altitude=940.0
    )
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.C
    assert any("altim" in n for n in res.properties[Property.POSITION].notes)


def test_s1_precision_trop_parfaite(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, h_accuracy=0.1)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.C


def test_s1_point_de_position_perime(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, fix_age_ms=90_000)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.C


def test_s1_ios_sans_corroboration_inertielle(nonces, key):
    """iOS n'a pas d'indicateur de mock : sans capteurs, aucun contrepoids."""
    devices = InMemoryDeviceStore()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(key),
            public_key=key.public_key(),
            platform="ios",
            hardware_backed=True,
        )
    )
    v = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.STRONG),
    )
    nonce = _issue(nonces)
    payload = make_payload(
        nonce=nonce,
        platform="ios",
        media_digest=MEDIA_DIGEST,
        with_motion=False,
        baro_altitude=None,
    )
    env = sign_envelope(key, payload, nonce=nonce, counter=1, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.C


# --- S2 : falsification de l'image --------------------------------------


def test_s2_image_ne_correspond_pas_a_lempreinte(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=b"une-autre-image")

    assert res.level is Level.REJECTED
    assert "MEDIA_DIGEST_MISMATCH" in res.flags


def test_s2_latence_de_signature_anormale(verifier, nonces, key):
    """Une caméra virtuelle allonge le délai entre capture et signature."""
    nonce = _issue(nonces)
    payload = make_payload(
        nonce=nonce, media_digest=MEDIA_DIGEST, sign_latency_ms=9_000
    )
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.ORIGIN].grade is Grade.C


# --- S3 : falsification temporelle --------------------------------------


def test_s3_nonce_rejoue(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    first = verifier.verify(env, media_bytes=MEDIA)
    second = verifier.verify(env, media_bytes=MEDIA)

    assert first.level is not Level.REJECTED
    assert second.level is Level.REJECTED
    assert "REPLAYED_NONCE" in second.flags


def test_s3_nonce_expire(verifier, nonces, key):
    nonce = _issue(nonces, ttl_ms=1_000)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA, now_ms=int(time.time() * 1000) + 60_000)

    assert res.level is Level.REJECTED
    assert "EXPIRED_NONCE" in res.flags


def test_s3_nonce_inconnu(verifier, key):
    nonce = os.urandom(16)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "UNKNOWN_NONCE" in res.flags


def test_s3_compteur_assertion_en_regression(nonces, key):
    devices = InMemoryDeviceStore()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(key),
            public_key=key.public_key(),
            platform="ios",
            hardware_backed=True,
            assertion_counter=42,
        )
    )
    v = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.STRONG),
    )
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, platform="ios", media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, counter=41, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "ASSERTION_COUNTER_REGRESSION" in res.flags


def test_s3_capture_hors_ligne_plafonnee(verifier, nonces, key):
    nonce = _issue(nonces, ttl_ms=86_400_000, offline=True)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.DEGRADED


# --- S4 : compromission du client ---------------------------------------


def test_s4_r1_defi_non_lie_au_contenu(verifier, nonces, key):
    """Jeton d'attestation authentique attaché à une charge utile forgée."""
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, bind_challenge=False)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.UNTRUSTED
    assert res.properties[Property.ORIGIN].grade is Grade.F


def test_s4_charge_utile_modifiee_apres_signature(verifier, nonces, key):
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, lat=48.2973)
    forged = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, lat=43.2965)
    env = sign_envelope(key, payload, nonce=nonce, tamper_payload_after_sign=forged)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "INVALID_SIGNATURE" in res.flags


def test_s4_un_seul_octet_modifie(verifier, nonces, key):
    nonce = _issue(nonces)
    env = bytearray(
        sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)
    )
    env[-1] ^= 0x01

    res = verifier.verify(bytes(env), media_bytes=MEDIA)

    assert res.level is Level.REJECTED


def test_s4_cle_inconnue(verifier, nonces):
    autre = new_key()
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(autre, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "UNKNOWN_KEY" in res.flags


def test_s4_integrite_appareil_en_echec(nonces, devices, key):
    v = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.FAILED),
    )
    nonce = _issue(nonces)
    env = sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    res = v.verify(env, media_bytes=MEDIA)

    assert res.level is Level.UNTRUSTED


# --- Robustesse au décodage ---------------------------------------------


def test_entree_illisible_rejetee(verifier):
    assert verifier.verify(b"\x00\x01\x02pas du cbor").level is Level.REJECTED


def test_algorithme_non_es256_refuse(verifier):
    env = cbor2.dumps(
        cbor2.CBORTag(18, [cbor2.dumps({1: -35, 100: "ac/0.1"}), {}, b"", b""])
    )
    res = verifier.verify(env)

    assert res.level is Level.REJECTED
    assert "MALFORMED_ENVELOPE" in res.flags


def test_version_de_spec_inconnue(verifier, key, nonces):
    import factory

    original = factory.SPEC
    factory.SPEC = "ac/9.9"
    try:
        nonce = _issue(nonces)
        env = sign_envelope(key, make_payload(nonce=nonce), nonce=nonce)
    finally:
        factory.SPEC = original

    res = verifier.verify(env)

    assert res.level is Level.REJECTED
    assert "UNSUPPORTED_SPEC_VERSION" in res.flags
