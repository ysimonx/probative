"""App Attest — validation de l'attestation d'enrôlement et des assertions.

Deux opérations de natures différentes, souvent confondues :

  * **l'attestation**, une fois par installation, prouve qu'une clé App
    Attest a été créée par la Secure Enclave d'un appareil Apple
    authentique, pour cette application. Elle se valide **hors ligne**
    contre la racine publiée par Apple — aucun serveur d'Apple n'est
    interrogé, ni ici ni sur l'appareil ;
  * **l'assertion**, à chaque enveloppe, prouve que cette même clé a
    signé ce contenu précis. C'est elle qui porte la règle R1.

Deux clés distinctes cohabitent sur l'appareil, et les confondre est
l'erreur qui coûte le plus cher à diagnostiquer :

  * la **clé de signature** du format, dans la Secure Enclave, désignée
    par le `kid` de l'en-tête protégé. Elle signe le `COSE_Sign1` ;
  * la **clé App Attest**, gérée par `DCAppAttestService`, qui ne sait
    rien signer d'arbitraire — elle ne produit que des assertions.

C'est la seconde qui vérifie les assertions, et le serveur ne la connaît
que parce qu'il l'a extraite du certificat feuille à l'enrôlement.

Référence : Apple, « Validating Apps That Connect to Your Server ».
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..errors import AttestationRejected
from .base import AttestationOutcome, AttestationVerifier, DeviceIntegrity

# Racine publiée par Apple, versionnée dans le dépôt : la validation doit
# fonctionner sans réseau, et l'ancre doit être auditable dans un diff.
# Une ancre téléchargée à l'exécution serait exactement la faiblesse que
# cette phase existe pour supprimer.
APPLE_ROOT_PEM = (
    Path(__file__).parent / "roots" / "apple-app-attest-root-ca.pem"
).read_bytes()

# Extension du certificat feuille portant le condensat du défi.
OID_NONCE = "1.2.840.113635.100.8.2"

# 16 octets exactement, complétés de zéros. L'environnement de
# développement et la production n'ont pas la même valeur : la confondre
# ferait passer en production des clés créées sur un appareil de test.
AAGUID_DEVELOPMENT = b"appattestdevelop"
AAGUID_PRODUCTION = b"appattest\x00\x00\x00\x00\x00\x00\x00"

_AAGUIDS = {
    "development": AAGUID_DEVELOPMENT,
    "production": AAGUID_PRODUCTION,
}


@dataclass(frozen=True)
class AppAttestEnrollment:
    """Ce que l'attestation établit, une fois pour l'installation."""

    key_id: bytes
    """Identifiant App Extest : SHA-256 de la clé publique du certificat feuille."""

    public_key_x962: bytes
    """Clé publique App Attest, seule capable de vérifier les assertions."""

    environment: str
    receipt: bytes
    """Reçu opaque. Sa validation exige un appel à Apple : hors périmètre ici."""


def _map(v: Any, what: str) -> Mapping[Any, Any]:
    if not isinstance(v, Mapping):
        raise AttestationRejected(f"{what} : map CBOR attendue")
    return v


def _blob(m: Mapping[Any, Any], key: str, what: str) -> bytes:
    v = m.get(key)
    if not isinstance(v, bytes):
        raise AttestationRejected(f"{what} : chaîne d'octets attendue pour {key!r}")
    return v


def _decode(raw: bytes, what: str) -> Mapping[Any, Any]:
    try:
        obj = cbor2.loads(raw)
    except Exception as exc:
        # Entrée hostile : un CBOR illisible est un rejet motivé, jamais
        # une exception qui remonte au serveur appelant.
        raise AttestationRejected(f"{what} : CBOR illisible") from exc
    return _map(obj, what)


def app_id_hash(team_id: str, bundle_id: str) -> bytes:
    """`rpIdHash` attendu : SHA-256 de « TEAMID.bundleId »."""
    return hashlib.sha256(f"{team_id}.{bundle_id}".encode()).digest()


def _verify_chain(x5c: Sequence[Any], root: x509.Certificate, now: datetime) -> x509.Certificate:
    """Valide `credCert ← intermédiaire ← racine` et rend le certificat feuille.

    On ne s'appuie pas sur un magasin système : l'ancre est celle passée
    en argument, et elle seule. Une chaîne cohérente mais rattachée à une
    autre racine ne prouve rien — c'est précisément ce que cette
    vérification existe pour empêcher.
    """
    if len(x5c) != 2:
        raise AttestationRejected(f"x5c : deux certificats attendus, {len(x5c)} reçus")
    try:
        certs = [x509.load_der_x509_certificate(c) for c in x5c]
    except Exception as exc:
        raise AttestationRejected("x5c : certificat DER illisible") from exc

    cred, intermediate = certs
    for cert, issuer, nom in (
        (intermediate, root, "intermédiaire"),
        (cred, intermediate, "feuille"),
    ):
        if cert.issuer != issuer.subject:
            raise AttestationRejected(f"certificat {nom} : émetteur inattendu")
        pub = issuer.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise AttestationRejected(f"certificat {nom} : émetteur non ECDSA")
        try:
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
            )
        except _CryptoInvalidSignature as exc:
            raise AttestationRejected(
                f"certificat {nom} : signature invalide sous son émetteur"
            ) from exc
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AttestationRejected(f"certificat {nom} : hors période de validité")

    return cred


def _public_key_x962(cert: x509.Certificate) -> bytes:
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise AttestationRejected("certificat feuille : clé publique non ECDSA")
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _nonce_extension(cert: x509.Certificate) -> bytes:
    """Extrait le condensat du défi de l'extension 1.2.840.113635.100.8.2.

    Le contenu est un `SEQUENCE { [1] { OCTET STRING } }`. On lit la
    structure plutôt que de chercher le condensat par sous-chaîne : une
    recherche par sous-chaîne accepterait un condensat placé n'importe
    où, y compris dans un champ que nous n'aurions pas prévu.
    """
    try:
        raw = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_NONCE)
        ).value.value  # type: ignore[attr-defined]
    except x509.ExtensionNotFound as exc:
        raise AttestationRejected("certificat feuille : extension de défi absente") from exc

    # DER minimal, sans dépendance : SEQUENCE > [1] > OCTET STRING.
    def _read(buf: bytes, tag: int, what: str) -> bytes:
        if len(buf) < 2 or buf[0] != tag:
            raise AttestationRejected(f"extension de défi : {what} attendu")
        length = buf[1]
        if length & 0x80:
            raise AttestationRejected("extension de défi : longueur longue inattendue")
        if len(buf) < 2 + length:
            raise AttestationRejected("extension de défi : contenu tronqué")
        return buf[2 : 2 + length]

    return _read(_read(_read(raw, 0x30, "SEQUENCE"), 0xA1, "[1]"), 0x04, "OCTET STRING")


@dataclass(frozen=True)
class _AuthenticatorData:
    rp_id_hash: bytes
    counter: int
    aaguid: bytes | None
    credential_id: bytes | None

    @classmethod
    def parse(cls, raw: bytes, *, with_credential: bool) -> _AuthenticatorData:
        minimum = 37
        if len(raw) < minimum:
            raise AttestationRejected(
                f"authenticatorData : {len(raw)} octets, au moins {minimum} attendus"
            )
        rp_id_hash = raw[0:32]
        counter = int.from_bytes(raw[33:37], "big")
        if not with_credential:
            return cls(rp_id_hash, counter, None, None)

        if len(raw) < 55:
            raise AttestationRejected("authenticatorData : bloc d'identifiant absent")
        aaguid = raw[37:53]
        cred_len = int.from_bytes(raw[53:55], "big")
        if len(raw) < 55 + cred_len:
            raise AttestationRejected("authenticatorData : identifiant tronqué")
        return cls(rp_id_hash, counter, aaguid, raw[55 : 55 + cred_len])


def verify_attestation(
    attestation: bytes,
    *,
    challenge: bytes,
    key_id: bytes,
    team_id: str,
    bundle_id: str,
    environment: str = "production",
    root_pem: bytes = APPLE_ROOT_PEM,
    now: datetime | None = None,
) -> AppAttestEnrollment:
    """Valide l'objet d'attestation d'enrôlement. Lève `AttestationRejected`.

    `challenge` est le défi d'enrôlement émis par le serveur, en clair :
    c'est lui qui empêche de rejouer une attestation obtenue ailleurs.
    """
    now = now or datetime.now(UTC)
    expected_aaguid = _AAGUIDS.get(environment)
    if expected_aaguid is None:
        connus = ", ".join(sorted(_AAGUIDS))
        raise AttestationRejected(f"environnement {environment!r} inconnu (attendu : {connus})")

    obj = _decode(attestation, "objet d'attestation")
    if obj.get("fmt") != "apple-appattest":
        raise AttestationRejected(f"format d'attestation inattendu : {obj.get('fmt')!r}")

    att_stmt = _map(obj.get("attStmt"), "attStmt")
    x5c = att_stmt.get("x5c")
    if not isinstance(x5c, Sequence) or isinstance(x5c, (bytes, str)):
        raise AttestationRejected("attStmt.x5c : tableau attendu")
    auth_data = _blob(obj, "authData", "objet d'attestation")

    root = x509.load_pem_x509_certificate(root_pem)
    cred = _verify_chain(x5c, root, now)

    # Le défi du serveur est lié à la clé par le certificat lui-même :
    # Apple y inscrit SHA-256(authData ‖ SHA-256(challenge)) au moment de
    # la création. C'est l'équivalent d'enrôlement de la règle R1.
    expected_nonce = hashlib.sha256(auth_data + hashlib.sha256(challenge).digest()).digest()
    if _nonce_extension(cred) != expected_nonce:
        raise AttestationRejected("défi d'enrôlement absent du certificat feuille")

    public_key = _public_key_x962(cred)
    if hashlib.sha256(public_key).digest() != key_id:
        raise AttestationRejected("keyId ne correspond pas à la clé du certificat feuille")

    ad = _AuthenticatorData.parse(auth_data, with_credential=True)
    if ad.rp_id_hash != app_id_hash(team_id, bundle_id):
        raise AttestationRejected("rpIdHash ne correspond pas à cette application")
    if ad.counter != 0:
        raise AttestationRejected(f"compteur d'attestation attendu à 0, reçu {ad.counter}")
    if ad.aaguid != expected_aaguid:
        raise AttestationRejected(
            f"environnement {environment!r} attendu, aaguid reçu {ad.aaguid!r}"
        )
    if ad.credential_id != key_id:
        raise AttestationRejected("identifiant de clé incohérent dans authenticatorData")

    receipt = att_stmt.get("receipt")
    return AppAttestEnrollment(
        key_id=key_id,
        public_key_x962=public_key,
        environment=environment,
        receipt=receipt if isinstance(receipt, bytes) else b"",
    )


class AppAttestVerifier(AttestationVerifier):
    """Valide l'assertion accompagnant chaque enveloppe.

    Ne juge que ce qu'App Attest établit : que la clé enrôlée a signé ce
    contenu, sur cette application. L'intégrité de l'appareil n'est pas un
    verdict séparé sur iOS — App Attest ne délivre rien sur une Secure
    Enclave absente ou un appareil non authentique, donc une assertion
    valide *est* le signal d'intégrité. C'est l'écart de fond avec
    Play Integrity, qui rend un verdict gradué.
    """

    def __init__(self, *, team_id: str, bundle_id: str) -> None:
        self._rp_id_hash = app_id_hash(team_id, bundle_id)

    def verify(
        self,
        *,
        platform: str,
        token: bytes,
        expected_challenge: bytes,
        key_id: bytes,
        attestation_key: bytes | None = None,
    ) -> AttestationOutcome:
        if platform != "ios":
            raise AttestationRejected(f"App Attest ne s'applique pas à la plateforme {platform!r}")
        if attestation_key is None:
            # Sans clé App Attest, il n'y a rien à vérifier. Rendre un
            # verdict favorable ici annulerait toute la phase.
            raise AttestationRejected("aucune clé App Attest enrôlée pour cet appareil")

        assertion = _decode(token, "assertion")
        auth_data = _blob(assertion, "authenticatorData", "assertion")
        signature = _blob(assertion, "signature", "assertion")

        ad = _AuthenticatorData.parse(auth_data, with_credential=False)
        if ad.rp_id_hash != self._rp_id_hash:
            raise AttestationRejected("assertion émise pour une autre application")

        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), attestation_key
            )
        except ValueError as exc:
            raise AttestationRejected("clé App Attest enrôlée illisible") from exc

        # Règle R1, appliquée cryptographiquement et non par comparaison
        # de champ : le `clientDataHash` ne circule pas dans l'enveloppe.
        # On le recalcule — c'est `expected_challenge` — et la signature
        # ne se vérifie que s'il est identique à celui que l'appareil a
        # réellement soumis. Un contenu forgé fait échouer la signature.
        nonce = hashlib.sha256(auth_data + expected_challenge).digest()
        try:
            public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        except _CryptoInvalidSignature as exc:
            raise AttestationRejected(
                "assertion invalide : la liaison R1 au contenu n'est pas établie"
            ) from exc

        return AttestationOutcome(
            integrity=DeviceIntegrity.STRONG,
            app_recognized=True,
            hardware_backed=True,
            counter=ad.counter,
            evidence=["app-attest:assertion-valid", "app-attest:r1-bound"],
        )
