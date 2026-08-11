"""Vérificateur de substitution, pour les tests et le développement local.

Accepte tout jeton dont le préfixe encode le verdict attendu. Ne doit
jamais être instancié en production : le constructeur l'inscrit dans les
notes du résultat pour que ce soit visible dans les journaux.
"""

from __future__ import annotations

from .base import AttestationOutcome, AttestationVerifier, DeviceIntegrity


class NullAttestationVerifier(AttestationVerifier):
    def __init__(self, integrity: DeviceIntegrity = DeviceIntegrity.STRONG) -> None:
        self.integrity = integrity

    def verify(
        self,
        *,
        platform: str,
        token: bytes,
        expected_challenge: bytes,
        key_id: bytes,
        attestation_key: bytes | None = None,
    ) -> AttestationOutcome:
        # Le jeton factice transporte le défi en clair : on vérifie
        # malgré tout R1, pour que les tests couvrent cette branche.
        if expected_challenge not in token:
            return AttestationOutcome(
                integrity=DeviceIntegrity.FAILED,
                app_recognized=False,
                hardware_backed=False,
                notes=["NullAttestationVerifier: défi R1 absent du jeton"],
            )
        return AttestationOutcome(
            integrity=self.integrity,
            app_recognized=True,
            hardware_backed=True,
            evidence=[f"null-verifier:{self.integrity.value}"],
            notes=["ATTENTION : NullAttestationVerifier actif, aucune attestation réelle"],
        )
