"""App Attest — implémentation à compléter après le spike iOS.

Rappels de conception issus du modèle de menace :

  * le `clientDataHash` de `generateAssertion` DOIT valoir le condensat
    R1, sans quoi la liaison au contenu est absente ;
  * le compteur d'assertion est strictement croissant et doit être
    persisté par installation — c'est ce qui donne à iOS un
    ordonnancement inviolable qu'Android n'a pas nativement ;
  * l'objet d'attestation initial se valide contre la racine App Attest
    d'Apple, une seule fois, à l'enrôlement.
"""

from __future__ import annotations

from .base import AttestationOutcome, AttestationVerifier


class AppAttestVerifier(AttestationVerifier):
    def verify(
        self,
        *,
        platform: str,
        token: bytes,
        expected_challenge: bytes,
        key_id: bytes,
    ) -> AttestationOutcome:
        raise NotImplementedError("à implémenter après le spike iOS")
