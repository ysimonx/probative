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
    integrity: DeviceIntegrity
    app_recognized: bool
    hardware_backed: bool
    counter: int | None = None
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
