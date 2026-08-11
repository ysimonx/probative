"""Phase D — App Attest, éprouvé contre une capture d'appareil réelle.

Tous les tests s'appuient sur `tests/device-vectors/appattest-c3-iphone16.json`,
produit par la sonde C3 sur un iPhone 16 sous iOS 26.6. Ce n'est pas une
fixture synthétique : c'est ce qu'Apple a réellement émis, et c'est la
raison pour laquelle ces tests valent quelque chose.

La chaîne remonte jusqu'à `roots/apple-app-attest-root-ca.pem`, la racine
publiée par Apple. C'est l'étape que le dépôt n'avait jamais franchie :
une chaîne cohérente se fabrique de toutes pièces, seule la confrontation
à l'ancre prouve quelque chose.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from probative.attestation import (
    APPLE_ROOT_PEM,
    AppAttestVerifier,
    DeviceIntegrity,
    app_id_hash,
    verify_attestation,
)
from probative.errors import AttestationRejected

VECTOR = Path(__file__).parent / "device-vectors" / "appattest-c3-iphone16.json"

# Identifiant d'équipe lu dans l'extension 1.2.840.113635.100.8.5 du
# certificat feuille du vecteur. Ce n'est pas un secret : il figure en
# clair dans toute application distribuée.
TEAM_ID = "9SGKL7VUD3"

# Le certificat feuille n'est valide que trois jours. Les tests se
# placent au moment de la capture, sinon ils cesseraient de passer sans
# qu'aucun code n'ait changé.
CAPTURE_TIME = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


def b64(s: str) -> bytes:
    return base64.b64decode(s)


@pytest.fixture(scope="module")
def vector() -> dict[str, Any]:
    return json.loads(VECTOR.read_text())


@pytest.fixture
def enroll_args(vector) -> dict[str, Any]:
    return {
        "attestation": b64(vector["enrollment"]["attestation"]),
        "challenge": b64(vector["enrollment"]["challenge"]),
        "key_id": b64(vector["keyId"]),
        "team_id": TEAM_ID,
        "bundle_id": vector["app"]["bundleId"],
        "environment": vector["app"]["environment"],
        "now": CAPTURE_TIME,
    }


def _retamper(attestation: bytes, mutate) -> bytes:
    """Décode l'objet d'attestation, le laisse modifier, le ré-encode."""
    obj = copy.deepcopy(cbor2.loads(attestation))
    mutate(obj)
    return cbor2.dumps(obj)


# --- Enrôlement : l'attestation ------------------------------------------


def test_attestation_reelle_validee_jusqua_la_racine_apple(enroll_args, vector):
    """Le jalon de la phase D : Apple a signé, et on l'a vérifié."""
    enrollment = verify_attestation(**enroll_args)

    assert enrollment.key_id == b64(vector["keyId"])
    assert enrollment.environment == "development"
    assert len(enrollment.public_key_x962) == 65
    assert enrollment.public_key_x962[0] == 0x04, "point X9.62 non compressé attendu"
    assert hashlib.sha256(enrollment.public_key_x962).digest() == enrollment.key_id
    assert enrollment.receipt, "le reçu doit être conservé pour un usage ultérieur"


def test_la_cle_app_attest_nest_pas_la_cle_de_signature(enroll_args, vector):
    """Deux clés distinctes vivent dans l'appareil — les confondre bloque tout."""
    enrollment = verify_attestation(**enroll_args)
    signing_key = b64(vector["signingKey"]["publicKeyX962"])

    assert enrollment.public_key_x962 != signing_key
    assert enrollment.key_id != b64(vector["signingKey"]["kid"])


def test_s4_racine_contrefaite_au_meme_nom_refusee(enroll_args):
    """Le test central de la phase D.

    On fabrique une racine parfaitement valide, portant **exactement le
    même sujet** que celle d'Apple, mais avec une autre clé. Tout
    contrôle fondé sur les noms passe ; seule la vérification de
    signature échoue. C'est précisément la réserve que cette phase existe
    pour lever — une chaîne cohérente se fabrique de toutes pièces, et
    sans confrontation à l'ancre publiée elle ne prouve rien.
    """
    vraie = x509.load_pem_x509_certificate(APPLE_ROOT_PEM)
    imposteur = ec.generate_private_key(ec.SECP384R1())
    contrefaite = (
        x509.CertificateBuilder()
        .subject_name(vraie.subject)  # au caractère près
        .issuer_name(vraie.subject)
        .public_key(imposteur.public_key())
        .serial_number(vraie.serial_number)
        .not_valid_before(vraie.not_valid_before_utc)
        .not_valid_after(vraie.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(imposteur, hashes.SHA384())
    )

    faux_pem = contrefaite.public_bytes(Encoding.PEM)
    assert x509.load_pem_x509_certificate(faux_pem).subject == vraie.subject

    with pytest.raises(AttestationRejected, match="signature invalide"):
        verify_attestation(**enroll_args | {"root_pem": faux_pem})


def test_s4_defi_denrolement_different_refuse(enroll_args):
    """Rejouer une attestation obtenue pour un autre défi."""
    with pytest.raises(AttestationRejected, match="défi d'enrôlement"):
        verify_attestation(**enroll_args | {"challenge": b"un-autre-defi"})


def test_s4_key_id_incoherent_refuse(enroll_args):
    with pytest.raises(AttestationRejected, match="keyId"):
        verify_attestation(**enroll_args | {"key_id": b"\x00" * 32})


def test_s4_autre_application_refusee(enroll_args):
    with pytest.raises(AttestationRejected, match="rpIdHash"):
        verify_attestation(**enroll_args | {"bundle_id": "org.probative.autre"})


def test_s4_autre_equipe_refusee(enroll_args):
    with pytest.raises(AttestationRejected, match="rpIdHash"):
        verify_attestation(**enroll_args | {"team_id": "AAAAAAAAAA"})


def test_environnement_de_production_refuse_une_cle_de_developpement(enroll_args):
    """La réserve connue du vecteur, transformée en test.

    L'aaguid distingue les deux environnements. Sans ce contrôle, une clé
    créée sur un appareil de développement passerait en production.
    """
    with pytest.raises(AttestationRejected, match="aaguid"):
        verify_attestation(**enroll_args | {"environment": "production"})


def test_environnement_inconnu_refuse(enroll_args):
    with pytest.raises(AttestationRejected, match="environnement"):
        verify_attestation(**enroll_args | {"environment": "recette"})


def test_certificat_expire_refuse(enroll_args):
    """Le certificat feuille ne vaut que trois jours."""
    tard = datetime(2027, 1, 1, tzinfo=UTC)
    with pytest.raises(AttestationRejected, match="validité"):
        verify_attestation(**enroll_args | {"now": tard})


def test_s4_chaine_tronquee_refusee(enroll_args):
    tronquee = _retamper(
        enroll_args["attestation"], lambda o: o["attStmt"].__setitem__("x5c", o["attStmt"]["x5c"][:1])
    )
    with pytest.raises(AttestationRejected, match="deux certificats"):
        verify_attestation(**enroll_args | {"attestation": tronquee})


def test_s4_format_dattestation_inattendu_refuse(enroll_args):
    autre = _retamper(enroll_args["attestation"], lambda o: o.__setitem__("fmt", "packed"))
    with pytest.raises(AttestationRejected, match="format"):
        verify_attestation(**enroll_args | {"attestation": autre})


@pytest.mark.parametrize(
    "octets", [b"", b"pas du cbor", cbor2.dumps([1, 2, 3]), cbor2.dumps({"fmt": 42})]
)
def test_s4_attestation_malformee_rejetee_proprement(enroll_args, octets):
    """Entrée hostile : un rejet motivé, jamais une exception non typée."""
    with pytest.raises(AttestationRejected):
        verify_attestation(**enroll_args | {"attestation": octets})


# --- Par enveloppe : l'assertion -----------------------------------------


@pytest.fixture
def verifier(vector) -> AppAttestVerifier:
    return AppAttestVerifier(team_id=TEAM_ID, bundle_id=vector["app"]["bundleId"])


@pytest.fixture
def assertion_args(vector, enroll_args) -> dict[str, Any]:
    a = vector["assertion"]
    return {
        "platform": "ios",
        "token": b64(a["assertion"]),
        # R1 recalculé, jamais lu dans l'enveloppe : c'est tout l'objet.
        "expected_challenge": hashlib.sha256(b64(a["payload"]) + b64(a["nonce"])).digest(),
        "key_id": b64(vector["signingKey"]["kid"]),
        "attestation_key": verify_attestation(**enroll_args).public_key_x962,
    }


def test_assertion_reelle_acceptee_et_r1_etablie(verifier, assertion_args, vector):
    out = verifier.verify(**assertion_args)

    assert out.integrity is DeviceIntegrity.STRONG
    assert out.app_recognized and out.hardware_backed
    assert "app-attest:r1-bound" in out.evidence
    assert out.counter == 1, "le compteur vient de authenticatorData, pas de l'enveloppe"


def test_r1_est_verifiee_par_la_signature_et_non_par_comparaison(verifier, assertion_args, vector):
    """Le `clientDataHash` ne circule pas : le vecteur le prouve.

    Le défi attendu est recalculé côté serveur. Si le contenu diffère
    d'un seul octet, le condensat change, et la signature de l'assertion
    ne se vérifie plus. Aucun champ n'est comparé — la liaison est
    cryptographique.
    """
    a = vector["assertion"]
    forge = hashlib.sha256(b64(a["payload"]) + b"\x00" + b64(a["nonce"])).digest()

    with pytest.raises(AttestationRejected, match="R1"):
        verifier.verify(**assertion_args | {"expected_challenge": forge})


def test_s4_assertion_sans_cle_enrolee_refusee(verifier, assertion_args):
    """Sans clé App Attest, il n'y a rien à vérifier — donc rien à accorder."""
    with pytest.raises(AttestationRejected, match="aucune clé"):
        verifier.verify(**assertion_args | {"attestation_key": None})


def test_s4_assertion_sous_une_autre_cle_refusee(verifier, assertion_args, vector):
    """La clé de signature du format ne valide pas les assertions."""
    with pytest.raises(AttestationRejected, match="R1|invalide"):
        verifier.verify(
            **assertion_args | {"attestation_key": b64(vector["signingKey"]["publicKeyX962"])}
        )


def test_s4_assertion_dune_autre_application_refusee(assertion_args, vector):
    autre = AppAttestVerifier(team_id=TEAM_ID, bundle_id="org.probative.autre")
    with pytest.raises(AttestationRejected, match="autre application"):
        autre.verify(**assertion_args)


def test_plateforme_android_refusee(verifier, assertion_args):
    with pytest.raises(AttestationRejected, match="plateforme"):
        verifier.verify(**assertion_args | {"platform": "android"})


@pytest.mark.parametrize(
    "octets", [b"", b"pas du cbor", cbor2.dumps({"signature": "pas des octets"})]
)
def test_s4_assertion_malformee_rejetee_proprement(verifier, assertion_args, octets):
    with pytest.raises(AttestationRejected):
        verifier.verify(**assertion_args | {"token": octets})


def test_app_id_hash_correspond_au_vecteur(vector, enroll_args):
    """Ancre le calcul de `rpIdHash` sur ce qu'Apple a réellement inscrit."""
    att = cbor2.loads(enroll_args["attestation"])
    assert app_id_hash(TEAM_ID, vector["app"]["bundleId"]) == att["authData"][0:32]
