"""Attestation de clé Android — la chaîne confrontée à la racine de Google.

Pendant Android de ce que la phase D a fait pour Apple, et la dernière
réserve de la boucle Android : jusqu'ici la chaîne était vérifiée
*cohérente avec elle-même*, jamais **ancrée**. Or une chaîne cohérente se
fabrique de toutes pièces — sans confrontation à l'ancre publiée, elle ne
prouve rien.

Deux propriétés en sortent, et elles ne se recouvrent pas :

- **l'ancrage** : la clé est née dans un composant que Google reconnaît ;
- **la liaison R1** : le défi que le TEE a inscrit dans l'extension vaut
  exactement `SHA-256(payload ‖ nonce)`. Sans elle, une attestation
  authentique obtenue ailleurs se recollerait sur n'importe quelle clé.

Rien ici n'interroge le réseau : l'attestation de clé est produite **hors
ligne** par la puce, ce qui est sa force. C'est l'écart avec Play
Integrity, qui exige un appel à Google pour chaque enveloppe.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..errors import AttestationRejected

GOOGLE_ROOTS_PEM = (
    Path(__file__).parent / "roots" / "google-hardware-attestation-roots.pem"
).read_bytes()

# KeyDescription, extension propriétaire de Keymaster/KeyMint.
OID_KEY_DESCRIPTION = "1.3.6.1.4.1.11129.2.1.17"

# `SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }`
NIVEAU_LOGICIEL = 0
NIVEAU_TEE = 1
NIVEAU_STRONGBOX = 2

_NOMS_NIVEAU = {
    NIVEAU_LOGICIEL: "Software",
    NIVEAU_TEE: "TrustedEnvironment",
    NIVEAU_STRONGBOX: "StrongBox",
}

# Position des champs de `KeyDescription` (spec Android). On lit par index
# plutôt qu'en cherchant le défi par sous-chaîne : une recherche par
# sous-chaîne accepterait un condensat placé dans n'importe quel champ, y
# compris un que nous n'aurions pas prévu.
_IDX_SECURITY_LEVEL = 1
_IDX_CHALLENGE = 4
_IDX_SOFTWARE_ENFORCED = 6
_IDX_TEE_ENFORCED = 7

# `[704] EXPLICIT RootOfTrust` dans une AuthorizationList.
#
# On ne le lit **que** dans `teeEnforced` : la même étiquette dans
# `softwareEnforced` ne serait garantie par rien, donc déclarative — et une
# valeur déclarative sur l'état du démarrage vérifié ne vaut rien du tout.
_TAG_ROOT_OF_TRUST = 704

# `VerifiedBootState ::= ENUMERATED { Verified, SelfSigned, Unverified, Failed }`
BOOT_STATES = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}


@dataclass(frozen=True)
class KeyAttestation:
    """Ce que la chaîne établit, une fois ancrée."""

    public_key_x962: bytes
    security_level: int
    challenge: bytes

    # `RootOfTrust`, lu dans la liste `teeEnforced` — donc garanti par le
    # composant sécurisé, et non déclaré par le système. `None` quand
    # l'appareil ne le publie pas : une absence n'est pas un échec, mais elle
    # n'est pas non plus une garantie, et rien ne doit la lire comme telle.
    device_locked: bool | None = None
    verified_boot_state: str | None = None

    @property
    def boot_verified(self) -> bool:
        """Démarrage vérifié **et** chargeur d'amorçage verrouillé.

        Les deux ensemble, jamais l'un sans l'autre : un état `Verified` sur
        un appareil déverrouillé signifie que l'image *présentée* était
        signée, pas que la chaîne de démarrage est close.
        """
        return self.device_locked is True and self.verified_boot_state == "Verified"

    @property
    def hardware_backed(self) -> bool:
        """StrongBox et TEE valent tous deux « adossé au matériel ».

        Les distinguer est le travail de la notation, pas du décodage : la
        SM-X200 n'a pas de StrongBox et sa clé est pourtant bien dans un
        composant sécurisé.
        """
        return self.security_level in (NIVEAU_TEE, NIVEAU_STRONGBOX)


def verify_key_attestation(
    chain: list[bytes],
    *,
    challenge: bytes,
    roots_pem: bytes = GOOGLE_ROOTS_PEM,
    now: datetime | None = None,
) -> KeyAttestation:
    """Valide la chaîne d'attestation et rend ce qu'elle établit.

    `chain` va de la feuille à la racine, en DER. `challenge` est le défi
    attendu — R1 à la capture, ou le défi d'enrôlement.

    Lève `AttestationRejected` : à l'enrôlement, une chaîne invalide est un
    refus d'enrôler, jamais un verdict nuancé.
    """
    now = now or datetime.now(UTC)
    if not chain:
        raise AttestationRejected("chaîne d'attestation vide")

    certs = [_charger(der, i) for i, der in enumerate(chain)]

    # 1. Chaque certificat est signé par le suivant, et dans sa validité.
    for i, cert in enumerate(certs):
        emetteur = certs[i + 1] if i + 1 < len(certs) else cert
        _verifier_signature(cert, emetteur, i)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AttestationRejected(
                f"certificat {i} : hors période de validité "
                f"({cert.not_valid_before_utc.date()} → {cert.not_valid_after_utc.date()})"
            )

    # 2. L'ancrage — le contrôle qui donne son sens à tout le reste.
    _ancrer(certs[-1], roots_pem)

    # 3. La liaison R1, par comparaison au défi inscrit par le composant.
    description = _key_description(certs[0])
    inscrit = description.challenge
    if not _egal(inscrit, challenge):
        raise AttestationRejected(
            "défi d'attestation différent de celui attendu : la clé n'a pas été "
            "engendrée pour cette charge utile"
        )

    if not description.hardware_backed:
        raise AttestationRejected(
            f"clé engendrée hors composant sécurisé "
            f"({_NOMS_NIVEAU.get(description.security_level, description.security_level)})"
        )

    return description


def _charger(der: bytes, index: int) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise AttestationRejected(f"certificat {index} illisible") from exc


def _verifier_signature(cert: x509.Certificate, emetteur: x509.Certificate, i: int) -> None:
    """Vérifie la signature de `cert` sous la clé d'`emetteur`.

    Les chaînes Android mêlent EC et RSA — la racine historique est
    RSA-4096, les intermédiaires sont en EC. Les deux doivent être traités,
    et tout autre type doit être refusé bruyamment plutôt qu'ignoré.
    """
    pub = emetteur.public_key()
    algo = cert.signature_hash_algorithm
    if algo is None:
        raise AttestationRejected(f"certificat {i} : algorithme de signature absent")
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(algo))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), algo)
        else:
            raise AttestationRejected(
                f"certificat {i} : clé d'émetteur de type inattendu {type(pub).__name__}"
            )
    except InvalidSignature as exc:
        raise AttestationRejected(
            f"certificat {i} : signature invalide sous son émetteur"
        ) from exc


def _ancrer(racine: x509.Certificate, roots_pem: bytes) -> None:
    """Confronte la racine de la chaîne aux racines publiées par Google.

    **L'ancrage porte sur la clé publique, jamais sur l'identité du
    certificat.** Google a réémis sa racine RSA en 2022 en conservant la
    clé : la SM-X200 porte une racine de série `d50ff25ba3f2d6b3`
    (2019-2034) quand Google publie aujourd'hui `f1c172a699eaf51d`
    (2022-2042). Même clé, certificats différents. Ancrer sur l'empreinte
    du certificat rejetterait une chaîne parfaitement légitime — et le
    défaut ne se verrait que sur du matériel ancien, donc tard.
    """
    attendues = {
        _spki(c) for c in x509.load_pem_x509_certificates(roots_pem)
    }
    if _spki(racine) not in attendues:
        raise AttestationRejected(
            "racine de la chaîne absente des racines publiées par Google : "
            "chaîne cohérente mais non ancrée"
        )


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def _key_description(feuille: x509.Certificate) -> KeyAttestation:
    """Décode l'extension `KeyDescription` du certificat feuille."""
    try:
        brut = feuille.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_KEY_DESCRIPTION)
        ).value.value  # type: ignore[attr-defined]
    except x509.ExtensionNotFound as exc:
        raise AttestationRejected(
            "certificat feuille : extension d'attestation de clé absente — "
            "cette clé n'a pas été engendrée avec un défi"
        ) from exc

    tag, contenu = _tlv(brut, 0)[0:2]
    if tag != 0x30:
        raise AttestationRejected("KeyDescription : SEQUENCE attendue")

    champs = _elements(contenu)
    if len(champs) <= _IDX_CHALLENGE:
        raise AttestationRejected(
            f"KeyDescription : {len(champs)} champs, au moins {_IDX_CHALLENGE + 1} attendus"
        )

    tag_niveau, valeur_niveau = champs[_IDX_SECURITY_LEVEL]
    if tag_niveau != 0x0A:
        raise AttestationRejected("attestationSecurityLevel : ENUMERATED attendu")

    tag_defi, valeur_defi = champs[_IDX_CHALLENGE]
    if tag_defi != 0x04:
        raise AttestationRejected("attestationChallenge : OCTET STRING attendu")

    pub = feuille.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise AttestationRejected("certificat feuille : clé publique non ECDSA")

    verrouille, etat = _root_of_trust(champs)

    return KeyAttestation(
        public_key_x962=pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        security_level=int.from_bytes(valeur_niveau, "big"),
        challenge=valeur_defi,
        device_locked=verrouille,
        verified_boot_state=etat,
    )


def _root_of_trust(champs: list[tuple[int, bytes]]) -> tuple[bool | None, str | None]:
    """Extrait `RootOfTrust` de la liste `teeEnforced`, si elle le publie.

    Lu dans `teeEnforced` **uniquement** : la même étiquette dans
    `softwareEnforced` ne serait garantie par rien. Une absence rend
    `(None, None)` — tous les appareils ne publient pas ce bloc, et
    l'inventer serait pire que de s'en passer.
    """
    if len(champs) <= _IDX_TEE_ENFORCED:
        return None, None
    bloc = _entree_contextuelle(champs[_IDX_TEE_ENFORCED][1], _TAG_ROOT_OF_TRUST)
    if bloc is None:
        return None, None

    tag, corps, _ = _tlv(bloc, 0)
    if tag != 0x30:
        raise AttestationRejected("RootOfTrust : SEQUENCE attendue")
    membres = _elements(corps)
    if len(membres) < 3:
        raise AttestationRejected(
            f"RootOfTrust : {len(membres)} champs, au moins 3 attendus"
        )

    tag_verrou, valeur_verrou = membres[1]
    if tag_verrou != 0x01:
        raise AttestationRejected("deviceLocked : BOOLEAN attendu")
    # DER impose 0xFF pour vrai, mais on lit « non nul » : un encodeur laxiste
    # ne doit pas faire passer un appareil verrouillé pour déverrouillé.
    verrouille = valeur_verrou != b"\x00"

    tag_etat, valeur_etat = membres[2]
    if tag_etat != 0x0A:
        raise AttestationRejected("verifiedBootState : ENUMERATED attendu")
    brut = int.from_bytes(valeur_etat, "big")
    etat = BOOT_STATES.get(brut)
    if etat is None:
        # Valeur hors nomenclature : on la rapporte telle quelle plutôt que
        # de la taire, et `boot_verified` la refusera de toute façon.
        etat = f"Inconnu({brut})"
    return verrouille, etat


def _entree_contextuelle(liste: bytes, numero: int) -> bytes | None:
    """Cherche `[numero] EXPLICIT` dans une `AuthorizationList`.

    Les numéros d'étiquette dépassent 30, donc la forme longue est
    obligatoire — c'est elle qui rend ce petit parcours nécessaire plutôt
    qu'un simple `_elements`.
    """
    position = 0
    while position < len(liste):
        octet = liste[position]
        if octet & 0x1F == 0x1F:
            curseur = position + 1
            trouve = 0
            while curseur < len(liste) and liste[curseur] & 0x80:
                trouve = (trouve << 7) | (liste[curseur] & 0x7F)
                curseur += 1
            if curseur >= len(liste):
                raise AttestationRejected("AuthorizationList : étiquette tronquée")
            trouve = (trouve << 7) | liste[curseur]
            entete = curseur + 1 - position
        else:
            trouve = octet & 0x1F
            entete = 1

        depart = position + entete
        if depart >= len(liste):
            raise AttestationRejected("AuthorizationList : entrée tronquée")
        longueur = liste[depart]
        depart += 1
        if longueur & 0x80:
            octets = longueur & 0x7F
            if octets == 0 or octets > 4 or depart + octets > len(liste):
                raise AttestationRejected("AuthorizationList : longueur invalide")
            longueur = int.from_bytes(liste[depart : depart + octets], "big")
            depart += octets
        if depart + longueur > len(liste):
            raise AttestationRejected("AuthorizationList : contenu tronqué")
        if trouve == numero:
            return liste[depart : depart + longueur]
        position = depart + longueur
    return None


# -- DER minimal ---------------------------------------------------------
#
# Suffisant pour KeyDescription, et rien de plus. Contrairement au lecteur
# d'App Attest, la forme longue est indispensable : la structure fait
# plusieurs centaines d'octets.


def _tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(buf):
        raise AttestationRejected("KeyDescription : structure tronquée")
    tag = buf[pos]
    pos += 1
    longueur = buf[pos]
    pos += 1
    if longueur & 0x80:
        octets = longueur & 0x7F
        if octets == 0 or octets > 4 or pos + octets > len(buf):
            raise AttestationRejected("KeyDescription : longueur invalide")
        longueur = int.from_bytes(buf[pos : pos + octets], "big")
        pos += octets
    if pos + longueur > len(buf):
        raise AttestationRejected("KeyDescription : contenu tronqué")
    return tag, buf[pos : pos + longueur], pos + longueur


def _elements(sequence: bytes) -> list[tuple[int, bytes]]:
    position = 0
    sortie: list[tuple[int, bytes]] = []
    while position < len(sequence):
        tag, valeur, position = _tlv(sequence, position)
        sortie.append((tag, valeur))
    return sortie


def _egal(a: bytes, b: bytes) -> bool:
    """Comparaison à temps constant, par principe : le défi est public, mais
    une comparaison naïve sur un secret futur passerait inaperçue ici."""
    return hmac.compare_digest(a, b)
