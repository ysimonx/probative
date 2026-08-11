"""Erreurs et codes de rejet.

Toute erreur porte un code stable, destiné à être remonté tel quel côté
support. Un rejet sans motif exploitable est un rejet inutilisable.
"""

from __future__ import annotations


class VerificationError(Exception):
    """Base de toutes les erreurs de vérification."""

    code = "UNSPECIFIED"

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(f"{self.code}: {detail}" if detail else self.code)


# --- Étapes 1 à 4 : rejets locaux, sans appel réseau ---------------------


class UnsupportedSpecVersion(VerificationError):
    code = "UNSUPPORTED_SPEC_VERSION"


class MalformedEnvelope(VerificationError):
    code = "MALFORMED_ENVELOPE"


class UnknownProfile(VerificationError):
    """Profil déclaré que ce vérificateur ne sait pas juger.

    Refuser est la seule issue correcte : juger avec le jeu de règles du
    noyau reviendrait à laisser tomber silencieusement les propriétés
    propres au profil, et donc son plafond éventuel.
    """

    code = "UNKNOWN_PROFILE"


class ProfileMismatch(VerificationError):
    """Le profil déclaré n'est pas celui pour lequel le nonce a été émis."""

    code = "PROFILE_MISMATCH"


class UnknownNonce(VerificationError):
    code = "UNKNOWN_NONCE"


class ExpiredNonce(VerificationError):
    code = "EXPIRED_NONCE"


class ReplayedNonce(VerificationError):
    code = "REPLAYED_NONCE"


class UnknownKey(VerificationError):
    code = "UNKNOWN_KEY"


class InvalidSignature(VerificationError):
    code = "INVALID_SIGNATURE"


class BindingMismatch(VerificationError):
    """Règle R1 violée : le défi d'attestation ne couvre pas cette charge utile."""

    code = "BINDING_MISMATCH"


# --- Étapes 5 et suivantes ---------------------------------------------


class AttestationRejected(VerificationError):
    code = "ATTESTATION_REJECTED"


class AssertionCounterRegression(VerificationError):
    code = "ASSERTION_COUNTER_REGRESSION"


class ChainBroken(VerificationError):
    code = "CHAIN_BROKEN"


class MediaDigestMismatch(VerificationError):
    code = "MEDIA_DIGEST_MISMATCH"
