"""Suite de vérification.

Les tests sont organisés en deux blocs : les cas nominaux, et les
scénarios d'attaque du modèle de menace. Chaque test d'attaque référence
la surface concernée — **S1 position, S2 contenu, S3 temps, S4 client**,
définies en `docs/threat-model.md` §4 bis. Une même surface peut ouvrir
plusieurs sections ici : le titre porte alors la surface *puis* le
scénario, pour qu'aucune section ne se fasse passer pour la définition.
"""

from __future__ import annotations

import hashlib
import os
import time

import cbor2
import pytest
from factory import PROFILE_CORE, kid_for, make_payload, new_key, sign_envelope

from probative import grading
from probative.attestation import (
    AttestationOutcome,
    DeviceIntegrity,
    NullAttestationVerifier,
)
from probative.grading import GradingPolicy
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


def _issue(nonces, key, profile=Profile.CAPTURE, **kw):
    nonce = os.urandom(16)
    nonces.issue(nonce, profile=profile, kid=kid_for(key), **kw)
    return nonce


# --- Cas nominaux -------------------------------------------------------


def test_capture_android_valide(verifier, nonces, key):
    nonce = _issue(nonces, key)
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
    nonce = _issue(nonces, key)
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
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, platform="ios", media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, counter=8, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.TIME].grade is Grade.A
    assert "assertion-counter-monotonic" in res.properties[Property.TIME].evidence


def test_reclamation_inconnue_signalee_sans_penalite(verifier, nonces, key):
    """Extensibilité : un type inconnu est signalé, jamais pénalisant."""
    nonce = _issue(nonces, key)
    payload = make_payload(
        nonce=nonce,
        media_digest=MEDIA_DIGEST,
        extra_claims=[{1: "wifi-v2", 2: "scan", 3: 4_300, 4: ["abc", "def"]}],
    )
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert "UNKNOWN_CLAIMS" in res.flags
    assert res.level is Level.STANDARD


# --- Politique de déploiement -------------------------------------------


def _verifier_avec(nonces, devices, policy):
    return Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.STRONG),
        policy=policy,
    )


def test_politique_par_defaut_ne_pollue_pas_le_resultat(verifier, nonces, key):
    """Un déploiement qui ne configure rien n'a rien à afficher."""
    nonce = _issue(nonces, key)
    env = sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.policy == []
    assert res.to_dict()["policy"] == []


def test_un_seuil_configure_change_le_grade_et_se_voit(nonces, devices, key):
    """Le cas d'usage réel : recalibrer un seuil sans toucher au code."""
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, fix_age_ms=30_000)
    env = sign_envelope(key, payload, nonce=nonce)

    # Par défaut, 30 s dépasse les 15 s tolérées.
    strict = _verifier_avec(nonces, devices, GradingPolicy())
    assert strict.verify(env, media_bytes=MEDIA).properties[Property.POSITION].grade is Grade.C

    # Un déploiement qui tolère des points plus vieux le déclare.
    nonce2 = _issue(nonces, key)
    payload2 = make_payload(nonce=nonce2, media_digest=MEDIA_DIGEST, fix_age_ms=30_000)
    env2 = sign_envelope(key, payload2, nonce=nonce2)
    large = _verifier_avec(nonces, devices, GradingPolicy(max_fix_age_ms=60_000))

    res = large.verify(env2, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.A
    assert "max_fix_age_ms=60000" in res.policy, "l'écart doit voyager avec le verdict"


def test_politique_de_distribution_hors_magasin(nonces, devices, key):
    """Le motif d'existence de ce mécanisme : la diffusion hors Play.

    Le vérificateur met par défaut la note la plus basse dès que le
    binaire n'est pas reconnu — ce qui revient à refuser toute diffusion
    hors magasin. Un déploiement interne peut vouloir dégrader plutôt que
    refuser ; il ne peut pas le faire en silence.
    """
    inconnu = NullAttestationVerifier(DeviceIntegrity.STRONG)
    inconnu.verify = lambda **kw: AttestationOutcome(  # type: ignore[method-assign]
        integrity=DeviceIntegrity.BASIC,
        app_recognized=False,
        hardware_backed=True,
        notes=["binaire distribué hors du magasin officiel"],
    )
    nonce = _issue(nonces, key)
    env = sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    v = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=inconnu,
        policy=GradingPolicy(unrecognized_app_grade=Grade.C),
    )
    res = v.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.ORIGIN].grade is Grade.C
    assert res.level is Level.DEGRADED, "dégradé, et non plus refusé"
    assert "unrecognized_app_grade=Grade.C" in res.policy


def _sortie_non_reconnue(empreinte: str | None) -> AttestationOutcome:
    return AttestationOutcome(
        integrity=DeviceIntegrity.BASIC,
        app_recognized=False,
        hardware_backed=True,
        app_certificate_digest=empreinte,
    )


def _verdict_avec(nonces, devices, key, sortie, policy):
    faux = NullAttestationVerifier(DeviceIntegrity.STRONG)
    faux.verify = lambda **kw: sortie  # type: ignore[method-assign]
    nonce = _issue(nonces, key)
    env = sign_envelope(
        key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce
    )
    v = Verifier(
        nonce_store=nonces, device_store=devices, attestation=faux, policy=policy
    )
    return v.verify(env, media_bytes=MEDIA)


NOTRE_CERT = "YxTPkqqTg9uWc30LWhHznOA_xp59hA2jJliTXMEIHZ8"


def test_binaire_signe_par_le_deploiement_est_degrade_pas_refuse(nonces, devices, key):
    """Notre propre build hors magasin ne doit pas subir le sort d'un APK reconditionné.

    Le magasin ne se porte pas garant des octets, mais la signature le fait :
    reconditionner impose de resigner, donc change l'empreinte, et le client
    ne calcule pas cette empreinte lui-même.
    """
    res = _verdict_avec(
        nonces,
        devices,
        key,
        _sortie_non_reconnue(NOTRE_CERT),
        GradingPolicy(trusted_app_certificates=(NOTRE_CERT,)),
    )

    origin = res.properties[Property.ORIGIN]
    assert origin.grade is Grade.C
    assert "app-deployment-signed" in origin.evidence
    # B ne conviendrait pas : le profil `capture` plafonne déjà `origin` à B,
    # une dégradation à B y serait donc invisible au niveau.
    assert res.level is Level.DEGRADED


def test_binaire_reconditionne_reste_au_sort_commun(nonces, devices, key):
    """Empreinte inconnue : c'est précisément le cas que la liste doit exclure."""
    res = _verdict_avec(
        nonces,
        devices,
        key,
        _sortie_non_reconnue("empreinte-d-un-attaquant"),
        GradingPolicy(trusted_app_certificates=(NOTRE_CERT,)),
    )

    origin = res.properties[Property.ORIGIN]
    assert origin.grade is Grade.F
    assert "app-deployment-signed" not in origin.evidence


def test_sans_liste_declaree_le_comportement_est_inchange(nonces, devices, key):
    """L'option resserre, elle ne desserre pas : liste vide = règles d'origine."""
    res = _verdict_avec(
        nonces, devices, key, _sortie_non_reconnue(NOTRE_CERT), GradingPolicy()
    )

    assert res.properties[Property.ORIGIN].grade is Grade.F
    assert res.policy == [], "aucun écart ne doit être déclaré"


def test_le_plafond_de_recapture_nest_pas_configurable():
    """Une option peut resserrer, jamais desserrer un angle mort assumé.

    Le rendre réglable permettrait à un déploiement de revendiquer
    `STRONG` sur des captures sans avoir implémenté la détection.
    """
    assert not hasattr(GradingPolicy(), "recapture_cap")
    assert grading.RECAPTURE_CAP is Grade.B


# --- Profils — ADR-0005 -------------------------------------------------


def test_profil_noyau_atteint_strong(verifier, nonces, key):
    """Le noyau n'affirme rien du monde physique : aucun plafond ne s'applique.

    Ce test est la contrepartie exacte du précédent. Tant que le plafond
    de recapture valait pour toute enveloppe, `STRONG` était inatteignable
    quel que soit le contenu — un journal signé était pénalisé par une
    attaque qui ne le concerne pas.
    """
    nonce = _issue(nonces, key, profile=Profile.CORE)
    payload = make_payload(nonce=nonce, profile=PROFILE_CORE, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile=PROFILE_CORE)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.profile == "core"
    assert res.properties[Property.ORIGIN].grade is Grade.A
    assert Property.POSITION not in res.properties, "le noyau ne note pas la position"


def test_le_motif_du_fournisseur_atteint_level_reason(verifier, nonces, key):
    """Les notes du vérificateur d'attestation doivent sortir du pipeline.

    Elles étaient purement et simplement perdues : seule `evidence` était
    reversée dans les propriétés. L'avertissement du substitut —
    « aucune attestation réelle » — n'apparaissait donc **nulle part**, et
    on pouvait faire tourner le faux vérificateur en production sans
    qu'aucun résultat ne le signale.
    """
    nonce = _issue(nonces, key)
    env = sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert any("NullAttestationVerifier" in n for n in res.properties[Property.ORIGIN].notes)
    assert "NullAttestationVerifier" in res.level_reason


def test_profil_noyau_signale_les_champs_non_notes(verifier, nonces, key):
    """Une position portée par une enveloppe `core` n'est jugée par rien.

    Elle est signée, donc d'apparence fiable, et n'a subi aucun contrôle —
    ni indicateur de position simulée, ni précision, ni corroboration. Le
    résultat omet la propriété `position`, ce qu'un lecteur attentif
    remarque ; le drapeau le dit à celui qui l'est moins.
    """
    nonce = _issue(nonces, key, profile=Profile.CORE)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)  # forme capture
    env = sign_envelope(key, payload, nonce=nonce, profile=PROFILE_CORE)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.profile == "core"
    assert Property.POSITION not in res.properties
    assert "UNGRADED_FIELDS" in res.flags


def test_profil_noyau_sans_champs_surnumeraires_ne_signale_rien(verifier, nonces, key):
    nonce = _issue(nonces, key, profile=Profile.CORE)
    payload = make_payload(nonce=nonce, profile=PROFILE_CORE, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile=PROFILE_CORE)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert "UNGRADED_FIELDS" not in res.flags


def test_profil_capture_accepte_une_duree_au_lieu_de_dimensions(verifier, nonces, key):
    """Le cas audio, qui justifie de ne pas lui ouvrir un profil propre.

    Un son n'a pas de dimensions mais une durée. Le profil `capture` exige
    l'un **ou** l'autre — c'est précisément ce qui fait tenir l'audio, la
    vidéo et l'image dans un seul profil, sans registre de types MIME.
    """
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    del payload[2][5]           # pas de largeur/hauteur
    payload[2][7] = 12_000      # mais une durée
    payload[2][3] = "audio/m4a"

    res = verifier.verify(sign_envelope(key, payload, nonce=nonce), media_bytes=MEDIA)

    assert res.profile == "capture"
    assert res.level is Level.STANDARD
    assert res.properties[Property.ORIGIN].grade is Grade.B, "le plafond vaut aussi pour le son"


def test_profil_capture_sans_dimensions_ni_duree_rejete(verifier, nonces, key):
    """Une acquisition qui ne décrit ni étendue ni durée ne décrit rien."""
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    del payload[2][5]

    res = verifier.verify(sign_envelope(key, payload, nonce=nonce), media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "durée" in res.level_reason


def test_profil_inconnu_refuse_de_juger(verifier, nonces, key):
    """Un profil non reconnu est un refus, jamais un repli sur le noyau.

    Le repli donnerait un verdict d'apparence complète, en ayant
    silencieusement omis les propriétés du profil et son plafond.
    """
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, profile="profil-de-demain")

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "UNKNOWN_PROFILE" in res.flags


def test_profil_absent_rejete(verifier, nonces, key):
    """Le label 102 est obligatoire : aucun défaut plausible n'est appliqué."""
    nonce = _issue(nonces, key)
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
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    del payload[3]
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "MALFORMED_ENVELOPE" in res.flags
    assert "position" in res.level_reason


# --- S4 : compromission du client — déclassement de profil ---------------


def test_s4_declassement_de_profil_par_le_nonce(verifier, nonces, key):
    """Déclarer le noyau pour une acquisition, afin d'échapper au plafond.

    Le profil est signé, donc non modifiable en vol — mais un client
    compromis reste libre de le *déclarer* faux dès l'origine. C'est le
    nonce qui ferme la porte : le serveur a demandé une acquisition, il
    doit en recevoir une.
    """
    nonce = _issue(nonces, key, profile=Profile.CAPTURE)
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
    nonce = _issue(nonces, key, profile=Profile.CORE)
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
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, mock_location=True)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.UNTRUSTED
    assert res.properties[Property.POSITION].grade is Grade.F


def test_s1_incoherence_altimetrique(verifier, nonces, key):
    """Un GPS téléporté ne s'accompagne pas d'un baromètre cohérent."""
    nonce = _issue(nonces, key)
    payload = make_payload(
        nonce=nonce, media_digest=MEDIA_DIGEST, altitude=112.0, baro_altitude=940.0
    )
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.C
    assert any("altim" in n for n in res.properties[Property.POSITION].notes)


def test_s1_precision_trop_parfaite(verifier, nonces, key):
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, h_accuracy=0.1)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.POSITION].grade is Grade.C


def test_s1_point_de_position_perime(verifier, nonces, key):
    nonce = _issue(nonces, key)
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
    nonce = _issue(nonces, key)
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


# --- S2 : falsification du contenu --------------------------------------


def test_s2_image_ne_correspond_pas_a_lempreinte(verifier, nonces, key):
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=b"une-autre-image")

    assert res.level is Level.REJECTED
    assert "MEDIA_DIGEST_MISMATCH" in res.flags


def test_s2_latence_de_signature_anormale(verifier, nonces, key):
    """Une caméra virtuelle allonge le délai entre capture et signature."""
    nonce = _issue(nonces, key)
    payload = make_payload(
        nonce=nonce, media_digest=MEDIA_DIGEST, sign_latency_ms=9_000
    )
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.ORIGIN].grade is Grade.C


# --- S3 : falsification temporelle --------------------------------------


def test_s3_nonce_rejoue(verifier, nonces, key):
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    first = verifier.verify(env, media_bytes=MEDIA)
    second = verifier.verify(env, media_bytes=MEDIA)

    assert first.level is not Level.REJECTED
    assert second.level is Level.REJECTED
    assert "REPLAYED_NONCE" in second.flags


def test_s3_nonce_expire(verifier, nonces, key):
    nonce = _issue(nonces, key, ttl_ms=1_000)
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


class _CounterVerifier(NullAttestationVerifier):
    """Substitut qui rend un compteur, comme le fera App Attest.

    Le compteur d'App Attest provient de `authenticatorData`, couvert par
    la signature de l'assertion. Celui de l'en-tête de fraîcheur ne l'est
    par rien.
    """

    def __init__(self, counter: int) -> None:
        super().__init__(DeviceIntegrity.STRONG)
        self._counter = counter

    def verify(self, **kw):  # type: ignore[override]
        out = super().verify(**kw)
        out.counter = self._counter
        return out


def _ios_verifier(nonces, key, attestation, counter=0):
    devices = InMemoryDeviceStore()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(key),
            public_key=key.public_key(),
            platform="ios",
            hardware_backed=True,
            assertion_counter=counter,
        )
    )
    return Verifier(nonce_store=nonces, device_store=devices, attestation=attestation)


def test_s3_compteur_declare_different_du_compteur_signe(nonces, key):
    """Le compteur de l'en-tête non protégé ne fait pas foi.

    Un client qui annonce 9 alors que l'assertion signée porte 3
    cherche à s'octroyer de la marge sur l'ordonnancement. Le désaccord
    est un rejet, pas un arbitrage silencieux en faveur de l'un des deux.
    """
    v = _ios_verifier(nonces, key, _CounterVerifier(3))
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, platform="ios", media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, counter=9, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "ASSERTION_COUNTER_REGRESSION" in res.flags
    assert "signé" in res.level_reason


def test_compteur_signe_fait_foi_pour_lordonnancement(nonces, key):
    """Quand les deux concordent, c'est le compteur signé qui est retenu."""
    v = _ios_verifier(nonces, key, _CounterVerifier(4), counter=3)
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, platform="ios", media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, counter=4, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.properties[Property.TIME].grade is Grade.A
    assert "assertion-counter-monotonic" in res.properties[Property.TIME].evidence


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
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, platform="ios", media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, counter=41, freshness_kind="app-attest")

    res = v.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "ASSERTION_COUNTER_REGRESSION" in res.flags


def test_s3_capture_hors_ligne_plafonnee(verifier, nonces, key):
    nonce = _issue(nonces, key, ttl_ms=86_400_000, offline=True)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.DEGRADED


# --- S4 : compromission du client — forge de preuves --------------------


def test_s4_r1_defi_non_lie_au_contenu(verifier, nonces, key):
    """Jeton d'attestation authentique attaché à une charge utile forgée."""
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(key, payload, nonce=nonce, bind_challenge=False)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.UNTRUSTED
    assert res.properties[Property.ORIGIN].grade is Grade.F


def test_s4_charge_utile_modifiee_apres_signature(verifier, nonces, key):
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, lat=48.2973)
    forged = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST, lat=43.2965)
    env = sign_envelope(key, payload, nonce=nonce, tamper_payload_after_sign=forged)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "INVALID_SIGNATURE" in res.flags


def test_s4_un_seul_octet_modifie(verifier, nonces, key):
    nonce = _issue(nonces, key)
    env = bytearray(
        sign_envelope(key, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)
    )
    env[-1] ^= 0x01

    res = verifier.verify(bytes(env), media_bytes=MEDIA)

    assert res.level is Level.REJECTED


def test_s4_cle_inconnue(verifier, nonces):
    """Clé non enrôlée. Le nonce est émis pour *elle*, sinon le rejet
    viendrait de la liaison à l'appareil et non de la clé inconnue —
    et ce test ne testerait plus ce qu'il annonce."""
    autre = new_key()
    nonce = _issue(nonces, autre)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    env = sign_envelope(autre, payload, nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "UNKNOWN_KEY" in res.flags


# --- S3 : falsification temporelle — moisson de nonces -------------------


def test_s3_nonce_dun_autre_appareil_refuse(verifier, nonces, key, devices):
    """Un nonce moissonné ne sert à aucun autre appareil, même enrôlé.

    C'est la contre-mesure à la moisson : la route d'émission est la seule
    qui crée de l'état sans preuve, et les lots hors ligne à durée de vie
    étendue en font un gisement. Sans liaison au `kid`, un attaquant
    disposant de son propre appareil enrôlé les consommerait.
    """
    autre = new_key()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(autre),
            public_key=autre.public_key(),
            platform="android",
            hardware_backed=True,
        )
    )
    nonce = _issue(nonces, key)  # émis pour le premier appareil
    env = sign_envelope(autre, make_payload(nonce=nonce, media_digest=MEDIA_DIGEST), nonce=nonce)

    res = verifier.verify(env, media_bytes=MEDIA)

    assert res.level is Level.REJECTED
    assert "NONCE_DEVICE_MISMATCH" in res.flags


def test_s3_un_nonce_presente_par_le_mauvais_appareil_nest_pas_brule(
    verifier, nonces, key, devices
):
    """Le détournement ne doit pas non plus servir de déni de service.

    Si un nonce présenté sous un mauvais `kid` était consommé au passage,
    il suffirait de le présenter une fois, avec une signature quelconque,
    pour empêcher son propriétaire de s'en servir.
    """
    autre = new_key()
    devices.enroll(
        DeviceRecord(
            kid=kid_for(autre),
            public_key=autre.public_key(),
            platform="android",
            hardware_backed=True,
        )
    )
    nonce = _issue(nonces, key)
    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    verifier.verify(sign_envelope(autre, payload, nonce=nonce), media_bytes=MEDIA)

    # Le propriétaire légitime s'en sert ensuite, sans encombre.
    res = verifier.verify(sign_envelope(key, payload, nonce=nonce), media_bytes=MEDIA)

    assert res.level is not Level.REJECTED, res.to_dict()


def test_s4_integrite_appareil_en_echec(nonces, devices, key):
    v = Verifier(
        nonce_store=nonces,
        device_store=devices,
        attestation=NullAttestationVerifier(DeviceIntegrity.FAILED),
    )
    nonce = _issue(nonces, key)
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
    nonce = _issue(nonces, key)
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
        nonce = _issue(nonces, key)
        env = sign_envelope(key, make_payload(nonce=nonce), nonce=nonce)
    finally:
        factory.SPEC = original

    res = verifier.verify(env)

    assert res.level is Level.REJECTED
    assert "UNSUPPORTED_SPEC_VERSION" in res.flags


# --- Conversion d'empreinte Play Console ----------------------------------


def test_empreinte_console_convertie_vers_la_forme_du_jeton():
    """Le format des deux consoles diffère : c'est la source d'erreur visée.

    L'empreinte de référence est celle réellement rapportée par Play
    Integrity pour `org.probative.demo` le 2026-08-12 ; l'hexadécimal est
    le même condensat, dans la forme qu'affiche la Play Console.
    """
    hexa = (
        "63:14:CF:92:AA:93:83:DB:96:73:7D:0B:5A:11:F3:9C:"
        "E0:3F:C6:9E:7D:84:0D:A3:26:58:93:5C:C1:08:1D:9F"
    )
    assert grading.app_certificate_digest(hexa) == NOTRE_CERT


@pytest.mark.parametrize(
    "forme",
    [
        "6314CF92AA9383DB96737D0B5A11F39CE03FC69E7D840DA32658935CC1081D9F",
        "6314cf92aa9383db96737d0b5a11f39ce03fc69e7d840da32658935cc1081d9f",
        (
            " 63:14:CF:92:AA:93:83:DB:96:73:7D:0B:5A:11:F3:9C:"
            "E0:3F:C6:9E:7D:84:0D:A3:26:58:93:5C:C1:08:1D:9F \n"
        ),
    ],
    ids=["sans-separateur", "minuscules", "avec-espaces"],
)
def test_empreinte_toleree_dans_ses_variantes_d_ecriture(forme):
    """Un copier-coller mal ajusté ne doit pas coûter une enquête."""
    assert grading.app_certificate_digest(forme) == NOTRE_CERT


@pytest.mark.parametrize(
    "entree",
    [NOTRE_CERT, "pas de l'hexa", "6314CF92", ""],
    ids=["deja-convertie", "charabia", "trop-courte", "vide"],
)
def test_empreinte_invalide_refusee_bruyamment(entree):
    """Accepter une valeur déjà convertie masquerait la confusion d'entrée.

    C'est le mode de défaillance que cette fonction existe pour supprimer :
    une empreinte mal formée doit échouer à la configuration, jamais
    produire un binaire silencieusement « non reconnu » en production.
    """
    with pytest.raises(ValueError):
        grading.app_certificate_digest(entree)
