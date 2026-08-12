"""Phase B — attestation de clé Android, éprouvée contre une capture réelle.

Le vecteur `device-vectors/keystore-a3-sm-x200.json` a été produit sur une
Samsung SM-X200 le 2026-08-11. Ce n'est pas une fixture synthétique : c'est
ce que le TEE a réellement émis.

Le test qui compte le plus est `test_chaine_forgee_de_bout_en_bout_refusee`.
Il fabrique une chaîne **parfaitement cohérente** — racine auto-signée,
intermédiaire, feuille portant le bon défi — et vérifie qu'elle est refusée.
C'est toute la différence entre « la chaîne se tient » et « la chaîne est
ancrée », et c'était la dernière réserve de la boucle Android.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from probative.attestation.key_attestation import (
    NIVEAU_LOGICIEL,
    NIVEAU_TEE,
    OID_KEY_DESCRIPTION,
    verify_key_attestation,
)
from probative.errors import AttestationRejected

VECTEUR = Path(__file__).parent / "device-vectors" / "keystore-a3-sm-x200.json"

# La chaîne réelle a été capturée le 2026-08-11 ; ses certificats courent
# jusqu'en 2031. On fige l'horloge : sans cela, ces tests deviendraient une
# bombe à retardement, exactement comme côté App Attest.
MAINTENANT = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def vecteur() -> dict:
    return json.loads(VECTEUR.read_text())


@pytest.fixture(scope="module")
def chaine(vecteur: dict) -> list[bytes]:
    return [base64.b64decode(c) for c in vecteur["attestation"]["chain"]]


@pytest.fixture(scope="module")
def defi(vecteur: dict) -> bytes:
    return base64.b64decode(vecteur["attestation"]["challenge"])


# --- Le vecteur réel ----------------------------------------------------


def test_chaine_reelle_ancree_et_liee(chaine: list[bytes], defi: bytes) -> None:
    r = verify_key_attestation(chaine, challenge=defi, now=MAINTENANT)

    assert r.security_level == NIVEAU_TEE
    assert r.hardware_backed is True
    assert r.challenge == defi


def test_le_defi_est_bien_r1_recalcule(vecteur: dict, chaine: list[bytes]) -> None:
    """Contrôle décisif, fait **par recalcul** et non par lecture de champ.

    Le TEE a inscrit un condensat dans son extension. On refait le calcul
    depuis la charge utile et le nonce : si les deux coïncident, la clé a
    bien été engendrée pour ce contenu précis.
    """
    payload = base64.b64decode(vecteur["attestation"]["payload"])
    nonce = base64.b64decode(vecteur["attestation"]["nonce"])
    r1 = hashlib.sha256(payload + nonce).digest()

    r = verify_key_attestation(chaine, challenge=r1, now=MAINTENANT)
    assert r.challenge == r1


def test_la_cle_attestee_est_celle_du_coeur(vecteur: dict, chaine: list[bytes], defi: bytes) -> None:
    """La clé du certificat feuille doit être celle qu'exporte le cœur."""
    r = verify_key_attestation(chaine, challenge=defi, now=MAINTENANT)
    kid = hashlib.sha256(r.public_key_x962).digest()

    assert base64.b64encode(kid).decode() == vecteur["key"]["kid"]


def test_la_racine_du_vecteur_differe_du_certificat_publie(chaine: list[bytes]) -> None:
    """Le piège que l'ancrage par clé publique évite.

    Google a réémis sa racine RSA en 2022 en conservant la clé. L'appareil
    porte donc un **certificat différent** de celui que Google publie
    aujourd'hui — série et validité distinctes, même clé. Un ancrage par
    empreinte de certificat aurait rejeté cette chaîne, et le défaut ne se
    serait vu que sur du matériel ancien, donc tard.
    """
    from probative.attestation.key_attestation import GOOGLE_ROOTS_PEM, _spki

    racine_appareil = x509.load_der_x509_certificate(chaine[-1])
    publiees = list(x509.load_pem_x509_certificates(GOOGLE_ROOTS_PEM))

    series_publiees = {c.serial_number for c in publiees}
    assert racine_appareil.serial_number not in series_publiees, (
        "le vecteur ne prouverait rien si les certificats étaient identiques"
    )
    assert _spki(racine_appareil) in {_spki(c) for c in publiees}


def test_deux_racines_sont_versionnees() -> None:
    """La racine EC de 2026 doit être acceptée : un appareil récent y chaîne."""
    from probative.attestation.key_attestation import GOOGLE_ROOTS_PEM

    racines = list(x509.load_pem_x509_certificates(GOOGLE_ROOTS_PEM))
    assert len(racines) == 2
    assert all(c.subject == c.issuer for c in racines), "racines auto-signées attendues"


# --- Fabrication d'une chaîne contrefaite -------------------------------


def _extension_key_description(defi: bytes, niveau: int = NIVEAU_TEE) -> bytes:
    """Construit une `KeyDescription` DER minimale mais bien formée."""

    def tlv(tag: int, contenu: bytes) -> bytes:
        if len(contenu) < 0x80:
            return bytes([tag, len(contenu)]) + contenu
        longueur = len(contenu).to_bytes((len(contenu).bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(longueur)]) + longueur + contenu

    corps = (
        tlv(0x02, b"\x03")            # attestationVersion
        + tlv(0x0A, bytes([niveau]))  # attestationSecurityLevel
        + tlv(0x02, b"\x04")          # keymasterVersion
        + tlv(0x0A, bytes([niveau]))  # keymasterSecurityLevel
        + tlv(0x04, defi)             # attestationChallenge
        + tlv(0x04, b"")              # uniqueId
        + tlv(0x30, b"")              # softwareEnforced
        + tlv(0x30, b"")              # teeEnforced
    )
    return tlv(0x30, corps)


def _chaine_forgee(defi: bytes, *, niveau: int = NIVEAU_TEE) -> list[bytes]:
    """Chaîne complète et cohérente, fabriquée de toutes pièces.

    C'est exactement ce qu'un attaquant sait produire : rien n'y manque, et
    seule la confrontation à l'ancre la démasque.
    """
    debut = MAINTENANT - timedelta(days=1)
    fin = MAINTENANT + timedelta(days=365)

    racine_key = ec.generate_private_key(ec.SECP384R1())
    feuille_key = ec.generate_private_key(ec.SECP256R1())

    nom_racine = x509.Name([x509.NameAttribute(NameOID.SERIAL_NUMBER, "f92009e853b6b045")])
    racine = (
        x509.CertificateBuilder()
        .subject_name(nom_racine)
        .issuer_name(nom_racine)
        .public_key(racine_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(racine_key, hashes.SHA384())
    )

    feuille = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Android Keystore Key")]))
        .issuer_name(nom_racine)
        .public_key(feuille_key.public_key())
        .serial_number(1)
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_KEY_DESCRIPTION),
                _extension_key_description(defi, niveau),
            ),
            critical=False,
        )
        .sign(racine_key, hashes.SHA384())
    )
    return [feuille.public_bytes(Encoding.DER), racine.public_bytes(Encoding.DER)]


def test_la_chaine_forgee_est_bien_coherente(defi: bytes) -> None:
    """Garde-fou du test suivant : sans lui, il pourrait passer pour une
    mauvaise raison — une chaîne cassée serait refusée avant l'ancrage."""
    forgee = _chaine_forgee(defi)
    racines = forgee[-1]

    r = verify_key_attestation(forgee, challenge=defi, roots_pem=_pem(racines), now=MAINTENANT)
    assert r.challenge == defi


def _pem(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM)


# --- Surface S4 : client ------------------------------------------------


def test_s4_chaine_forgee_de_bout_en_bout_refusee(defi: bytes) -> None:
    """LE test de la phase B côté Android.

    La chaîne est cohérente, la racine porte le même sujet que celle de
    Google, le défi est le bon. Seule l'absence d'ancrage la démasque.
    """
    with pytest.raises(AttestationRejected, match="non ancrée"):
        verify_key_attestation(_chaine_forgee(defi), challenge=defi, now=MAINTENANT)


def test_s4_defi_d_une_autre_charge_utile(chaine: list[bytes]) -> None:
    """L'attestation authentique ne doit pas se recoller ailleurs."""
    autre = hashlib.sha256(b"une autre charge utile").digest()

    with pytest.raises(AttestationRejected, match="défi d'attestation"):
        verify_key_attestation(chaine, challenge=autre, now=MAINTENANT)


def test_s4_cle_logicielle_refusee(defi: bytes) -> None:
    """Une clé hors composant sécurisé n'atteste rien du matériel."""
    forgee = _chaine_forgee(defi, niveau=NIVEAU_LOGICIEL)

    with pytest.raises(AttestationRejected, match="hors composant sécurisé"):
        verify_key_attestation(
            forgee, challenge=defi, roots_pem=_pem(forgee[-1]), now=MAINTENANT
        )


def test_s4_feuille_alteree_refusee(chaine: list[bytes], defi: bytes) -> None:
    """Un octet modifié dans la feuille casse sa signature."""
    altere = bytearray(chaine[0])
    altere[-1] ^= 0x01
    corrompue = [bytes(altere), *chaine[1:]]

    with pytest.raises(AttestationRejected, match="signature invalide"):
        verify_key_attestation(corrompue, challenge=defi, now=MAINTENANT)


# --- Cas structurels ----------------------------------------------------


def test_horloge_hors_validite(chaine: list[bytes], defi: bytes) -> None:
    """L'horloge est injectable, sans quoi ce test deviendrait une bombe."""
    tard = datetime(2099, 1, 1, tzinfo=UTC)

    with pytest.raises(AttestationRejected, match="période de validité"):
        verify_key_attestation(chaine, challenge=defi, now=tard)


def test_chaine_vide(defi: bytes) -> None:
    with pytest.raises(AttestationRejected, match="vide"):
        verify_key_attestation([], challenge=defi, now=MAINTENANT)


def test_certificat_illisible(defi: bytes) -> None:
    with pytest.raises(AttestationRejected, match="illisible"):
        verify_key_attestation([b"pas du DER"], challenge=defi, now=MAINTENANT)


def test_extension_absente(defi: bytes) -> None:
    """Une clé engendrée sans défi ne porte pas l'extension d'attestation."""
    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sans attestation")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(1)
        .not_valid_before(MAINTENANT - timedelta(days=1))
        .not_valid_after(MAINTENANT + timedelta(days=1))
        .sign(cle, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)

    with pytest.raises(AttestationRejected, match="extension d'attestation"):
        verify_key_attestation([der], challenge=defi, roots_pem=_pem(der), now=MAINTENANT)
