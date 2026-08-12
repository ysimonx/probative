"""Interface des vérificateurs d'attestation de plateforme.

L'appel réel à Play Integrity ou App Attest est une dépendance réseau.
Il est isolé derrière cette interface pour que l'intégralité de la
logique de vérification reste testable hors ligne.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class DeviceIntegrity(str, Enum):
    """Verdict normalisé, commun aux deux plateformes."""

    STRONG = "STRONG"      # Android MEETS_STRONG_INTEGRITY / iOS App Attest + Secure Enclave
    BASIC = "BASIC"        # Android MEETS_DEVICE_INTEGRITY
    FAILED = "FAILED"      # appareil compromis, émulé, ou binaire non reconnu
    UNAVAILABLE = "UNAVAILABLE"  # service injoignable — n'est pas un échec de l'appareil


@dataclass
class AttestationOutcome:
    """Faits normalisés rendus par le fournisseur. **Aucun jugement ici.**

    `app_recognized` dit uniquement si le *magasin* reconnaît le binaire. Il
    reste booléen à dessein : c'est le verdict du fournisseur, pas une note.
    Savoir si un binaire non reconnu par le magasin est malgré tout le nôtre
    relève d'une politique de déploiement — donc de `GradingPolicy`, qui
    confronte `app_certificate_digest` à ses empreintes autorisées. Le
    vérificateur rapporte, la notation juge.
    """

    integrity: DeviceIntegrity
    app_recognized: bool
    hardware_backed: bool
    counter: int | None = None

    # Empreinte SHA-256 du certificat de signature de l'application, telle que
    # le fournisseur la calcule — donc non falsifiable par le client. C'est
    # elle qui distingue un binaire reconditionné, forcément resigné avec une
    # autre clé, d'une build authentique diffusée hors du magasin.
    app_certificate_digest: str | None = None

    # Instant que le fournisseur date lui-même. Sur Android, Play Integrity
    # l'inscrit dans le jeton, lié à la charge utile par le même `requestHash`
    # — donc une borne haute posée par un tiers, et non par le client. iOS n'a
    # pas d'équivalent avant que les extensions d'iOS 27 ne soient exploitées :
    # ce champ reste optionnel, et aucune propriété ne doit l'exiger.
    provider_timestamp_ms: int | None = None

    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class AttestationVerifier(ABC):
    @abstractmethod
    def verify(
        self,
        *,
        platform: str,
        token: bytes,
        expected_challenge: bytes,
        key_id: bytes,
        attestation_key: bytes | None = None,
    ) -> AttestationOutcome:
        """Valide le jeton auprès du fournisseur et normalise le verdict.

        `expected_challenge` est le résultat de la règle R1. Une
        implémentation qui ne le compare pas au défi contenu dans le
        jeton est incorrecte, quelle que soit sa validation par ailleurs.

        `attestation_key` est la clé publique retenue à l'enrôlement pour
        valider les preuves de fraîcheur, distincte de la clé qui signe
        l'enveloppe. iOS en a besoin — l'assertion App Attest est signée
        par la clé de `DCAppAttestService`, pas par celle du `kid`.
        Android l'ignore : le jeton Play Integrity est signé par Google.
        """
