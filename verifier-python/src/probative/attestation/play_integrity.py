"""Play Integrity — implémentation à compléter (phase B du spike).

La contrainte de taille sur `requestHash` est levée : base64url sans
bourrage, 43 caractères pour un plafond de 500. Restent trois points, que
seul le déchiffrement d'un jeton réel permettra de trancher :

  * **Play restitue-t-il la chaîne intacte ?** Une divergence d'encodage
    entre client et serveur casserait R1 *silencieusement* — le pire mode
    de défaillance, et la raison de ne pas figer ADR-0002 avant.
  * **Où se déchiffre le jeton ?** Localement avec des clés détenues, ou
    par un appel à Google. L'écart n'est pas mineur : un appel par
    enveloppe ajoute une latence, une limite de débit et une dépendance
    de disponibilité en plein chemin de vérification.
  * le taux d'échec sur appareils sains d'entrée de gamme, qui
    conditionne le critère de faux positifs du modèle de menace.

Contrairement à App Attest, le verdict est **gradué** — l'appareil et
l'application sont jugés séparément (`appRecognitionVerdict`,
`deviceRecognitionVerdict`), et `AttestationOutcome` a été dessiné pour
recevoir cette granularité.
"""

from __future__ import annotations

from .base import AttestationOutcome, AttestationVerifier


class PlayIntegrityVerifier(AttestationVerifier):
    def verify(
        self,
        *,
        platform: str,
        token: bytes,
        expected_challenge: bytes,
        key_id: bytes,
        attestation_key: bytes | None = None,
    ) -> AttestationOutcome:
        raise NotImplementedError("à implémenter en phase B du spike")
