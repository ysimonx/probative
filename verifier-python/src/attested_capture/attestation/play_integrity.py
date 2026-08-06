"""Play Integrity — implémentation à compléter après le spike Android.

Points à valider sur appareil réel avant d'écrire ce module :

  * la contrainte de taille sur `requestHash` — si le condensat R1 de
    32 octets ne passe pas tel quel, il faut un niveau d'indirection
    (stocker le condensat côté serveur, transmettre une référence) ;
  * la différence entre requêtes classiques et standard, et laquelle
    autorise réellement la liaison au contenu ;
  * le taux d'échec sur appareils sains d'entrée de gamme, qui
    conditionne le critère de faux positifs du modèle de menace.
"""

from __future__ import annotations

from .base import AttestationOutcome, AttestationVerifier


class PlayIntegrityVerifier(AttestationVerifier):
    def verify(self, **kwargs) -> AttestationOutcome:  # noqa: D102
        raise NotImplementedError("à implémenter après le spike Android")
