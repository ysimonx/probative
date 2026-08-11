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
from factory import PROFILE_CORE, kid_for, make_payload, new_key, sign_envelope

from probative.attestation import DeviceIntegrity, NullAttestationVerifier
from probative.model import Grade, Level, Profile, Property
from probative.store import (
    DeviceRecord,
    InMemoryDeviceStore,
    InMemoryNonceStore,
)
from probative.verifier import Verifier

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


def _issue(nonces, profile=Profile.CAPTURE, **kw):
    nonce = os.urandom(16)
    nonces.issue(nonce, profile=profile, **kw)
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


def test_origin_plafonne_par_recapture_en_v01(verifier, nonces, key):
    """Profil capture : la recapture analogique n'étant pas détectée, origin ≤ B.

    Photographier un écran et enregistrer un haut-parleur sont la même
    attaque. Le plafond porte donc sur le profil, pas sur le médium.
    """
    nonce = _issue(nonces)
    env = sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.profile == "capture"
    assert res.properties[Property.ORIGIN].grade is Grade.B
    assert any("recapture" in n for n in res.properties[Property.ORIGIN].notes)
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


# --- Profils — ADR-0005 -------------------------------------------------


def test_profil_noyau_atteint_strong(verifier, nonces, key):
    """Le noyau n'affirme rien du monde physique : aucun plafond ne s'applique.

    Ce test est la contrepartie exacte du précédent. Tant que le plafond
    de recapture valait pour toute enveloppe, `STRONG` était inatteignable
    quel que soit le contenu — un journal signé était pénalisé par une
    attaque qui ne le concerne pas.
    """
    nonce = _issue(nonces, profile=Profile.CORE)
    payload = make_payload(nonce=nonce, profile=PROFILE_CORE, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile=PROFILE_CORE)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.profile == "core"
    assert res.properties[Property.ORIGIN].grade is Grade.A
    assert Property.POSITION not in res.properties, "le noyau ne note pas la position"


def test_profil_inconnu_refuse_de_juger(verifier, nonces, key):
    """Un profil non reconnu est un refus, jamais un repli sur le noyau.

    Le repli donnerait un verdict d'apparence complète, en ayant
    silencieusement omis les propriétés du profil et son plafond.
    """
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile="profil-de-demain")

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "UNKNOWN_PROFILE" in res.flags


def test_profil_absent_rejete(verifier, nonces, key):
    """Le label 102 est obligatoire : aucun défaut plausible n'est appliqué."""
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    protected = cbor2.dumps(
        {1: -7, 4: kid_for(key), 100: "probative/0.1", 101: "test-deployment"},
        canonical=True,
    )
    env = _reassemble(sign_envelope(key, payload, nonce=nonce), protected)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "MALFORMED_ENVELOPE" in res.flags


def test_profil_capture_sans_position_rejete(verifier, nonces, key):
    """`position` est optionnelle au schéma, obligatoire dans le profil capture."""
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    del payload[3]
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "MALFORMED_ENVELOPE" in res.flags
    assert "position" in res.level_reason


# --- S4 : déclassement de profil ----------------------------------------


def test_s4_declassement_de_profil_par_le_nonce(verifier, nonces, key):
    """Déclarer le noyau pour une acquisition, afin d'échapper au plafond.

    Le profil est signé, donc non modifiable en vol — mais un client
    compromis reste libre de le *déclarer* faux dès l'origine. C'est le
    nonce qui ferme la porte : le serveur a demandé une acquisition, il
    doit en recevoir une.
    """
    nonce = _issue(nonces, profile=Profile.CAPTURE)
    payload = make_payload(nonce=nonce, profile=PROFILE_CORE, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile=PROFILE_CORE)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "PROFILE_MISMATCH" in res.flags


def test_s4_profil_reecrit_apres_signature(verifier, nonces, key):
    """Le profil vit dans l'en-tête protégé : le réécrire casse la signature.

    Le nonce est ici émis pour le noyau, de sorte que le déclassement
    passerait le contrôle précédent. C'est la signature, et elle seule,
    qui l'arrête — ce qui est bien la raison de mettre le label en 102 et
    non dans la charge utile.
    """
    nonce = _issue(nonces, profile=Profile.CORE)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile="capture")
    declasse = cbor2.dumps(
        {
            1: -7,
            4: kid_for(key),
            100: "probative/0.1",
            101: "test-deployment",
            102: "core",
        },
        canonical=True,
    )

    res = verifier.verify(_reassemble(env, declasse), media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "INVALID_SIGNATURE" in res.flags


def _reassemble(envelope: bytes, protected: bytes) -> bytes:
    """Remplace l'en-tête protégé sans retoucher au reste de l'enveloppe."""
    _, unprotected, payload_bytes, signature = cbor2.loads(envelope).value
    return cbor2.dumps(
        cbor2.CBORTag(18, [protected, unprotected, payload_bytes, signature]),
        canonical=True,
    )


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


def test_charge_utile_illisible_rejetee(verifier, key):
    """Une enveloppe bien formée dont la charge utile n'est pas du CBOR.

    Le décodage de la charge utile précède la vérification de signature :
    c'est donc une porte d'entrée atteignable sans aucune clé.
    """
    protected = cbor2.dumps(
        {1: -7, 4: kid_for(key), 100: "probative/0.1", 101: "test-deployment"}, canonical=True
    )
    env = cbor2.dumps(
        cbor2.CBORTag(
            18,
            [
                protected,
                {200: {1: "play-integrity", 2: b"jeton"}},
                b"\xff\xff\xff",
                b"\x00" * 64,
            ],
        ),
        canonical=True,
    )
    res = verifier.verify(env)

    assert res.level is Level.REJECTED
    assert res.flags == ["MALFORMED_ENVELOPE"]


# Chemin dans la charge utile, puis valeur du mauvais type. Chaque cas est
# du CBOR parfaitement valide : seule la conformité au schéma est violée.
CHAMPS_MAL_TYPES = [
    ((2,), "pas-une-map"),          # media n'est pas une map
    ((2,), 42),
    ((3,), [1, 2, 3]),              # position n'est pas une map
    ((5,), b"octets"),              # posture n'est pas une map
    ((6,), 7),                      # corroboration n'est pas un tableau
    ((5, 8), 3),                    # paquets suspects n'est pas un tableau
    ((5, 8), [1, 2]),               # ...et ses éléments doivent être des chaînes
    ((3, 1), "48.29"),              # latitude en chaîne
    ((3, 3), "huit"),               # précision horizontale en chaîne
    ((3, 7), -1),                   # âge du point négatif
    ((2, 6), "lente"),              # latence en chaîne
    ((2, 5), [4032]),               # dimensions incomplètes
    ((4, 1), "hier"),               # horloge murale en chaîne
    ((5, 4), "non"),                # débogueur non booléen
    ((1,), "nonce-en-clair"),       # nonce en chaîne au lieu d'octets
]


@pytest.mark.parametrize(("chemin", "valeur"), CHAMPS_MAL_TYPES)
def test_s4_champ_mal_type_rejete(verifier, nonces, key, chemin, valeur):
    """Une charge utile conforme au CBOR mais pas au schéma est rejetée.

    Le point n'est pas seulement qu'elle soit refusée, c'est qu'elle le
    soit par un rejet motivé. Une exception qui remonterait au serveur
    appelant transformerait une enveloppe malformée en incident, et un
    champ mal typé qui traverserait le calcul des grades sans être
    remarqué serait pire encore.
    """
    nonce = _issue(nonces)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)

    cible = payload
    for k in chemin[:-1]:
        cible = cible[k]
    cible[chemin[-1]] = valeur

    res = verifier.verify(sign_envelope(key, payload, nonce=nonce), media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert res.flags == ["MALFORMED_ENVELOPE"]
    assert res.level_reason, "un rejet doit toujours porter son motif"


def test_algorithme_non_es256_refuse(verifier):
    env = cbor2.dumps(
        cbor2.CBORTag(18, [cbor2.dumps({1: -35, 100: "probative/0.1"}), {}, b"", b""])
    )
    res = verifier.verify(env)

    assert res.level is Level.REJECTED
    assert "MALFORMED_ENVELOPE" in res.flags


def test_version_de_spec_inconnue(verifier, key, nonces):
    import factory

    original = factory.SPEC
    factory.SPEC = "probative/9.9"
    try:
        nonce = _issue(nonces)
        env = sign_envelope(key, make_payload(nonce=nonce), nonce=nonce)
    finally:
        factory.SPEC = original

    res = verifier.verify(env)

    assert res.level is Level.REJECTED
    assert "UNSUPPORTED_SPEC_VERSION" in res.flags
