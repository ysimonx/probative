"""Persistance requise par le vérificateur.

Trois états doivent survivre entre deux captures, et aucun ne peut être
confié au client :

  * les nonces émis, pour la règle R3 ;
  * les clés publiques enrôlées, pour la règle R2 ;
  * le compteur d'assertion et le dernier condensat d'enveloppe, pour
    l'ordonnancement.

Les implémentations mémoire ci-dessous servent aux tests. En production,
`NonceStore.consume` doit être atomique — un `UPDATE ... WHERE consumed_at
IS NULL AND kid = ?` avec vérification du nombre de lignes affectées,
jamais un `SELECT` suivi d'un `UPDATE`, sous peine de rejeu par course.

Le `kid` fait partie de la condition, et pas seulement d'un contrôle qui
suivrait : un nonce présenté par le mauvais appareil ne doit pas être
consommé, sinon il suffirait de le présenter une fois avec une signature
quelconque pour le brûler.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from .errors import (
    ExpiredNonce,
    NonceDeviceMismatch,
    ReplayedNonce,
    UnknownKey,
    UnknownNonce,
)
from .model import Profile


@dataclass
class NonceRecord:
    """Un nonce est émis *pour* un appareil et *pour* un profil.

    Le profil est le pendant serveur du label 102 : le profil signé dit ce
    que le client a produit, celui du nonce dit ce que le serveur a
    demandé. Sans le second, un client compromis déclarerait le noyau pour
    une acquisition et échapperait au plafond de recapture.

    Le `kid` ferme la moisson. Un nonce n'est ni un secret ni un droit
    d'accès — le connaître ne permet pas de forger, puisqu'il faut encore
    une clé matérielle enrôlée et une attestation liée au contenu. Mais
    sans liaison à l'appareil, un lot moissonné servirait à **n'importe
    quel appareil enrôlé, y compris celui de l'attaquant**, et les lots
    hors ligne à durée de vie étendue en font un gisement.

    La spec §6 pose que le contexte applicatif est lié par le nonce, côté
    serveur : ces deux champs en sont l'application.
    """

    value: bytes
    issued_at_ms: int
    ttl_ms: int
    profile: Profile
    kid: bytes
    offline: bool = False
    consumed_at_ms: int | None = None


@dataclass
class DeviceRecord:
    kid: bytes
    public_key: ec.EllipticCurvePublicKey
    platform: str
    hardware_backed: bool
    assertion_counter: int = 0
    last_envelope_digest: bytes | None = None
    attestation_key: bytes | None = None
    """Clé publique de fraîcheur retenue à l'enrôlement, X9.62 non compressée.

    Distincte de `public_key`, qui vérifie la signature de l'enveloppe.
    Sur iOS, l'assertion App Attest est signée par la clé de
    `DCAppAttestService`, que le serveur ne connaît que pour l'avoir
    extraite du certificat feuille de l'attestation. Android n'en a pas
    besoin : le jeton Play Integrity est signé par Google.
    """


class NonceStore(ABC):
    @abstractmethod
    def consume(self, nonce: bytes, now_ms: int, *, kid: bytes) -> NonceRecord:
        """Consomme un nonce pour un appareil donné, ou lève.

        Le `kid` est celui que l'enveloppe *déclare*, pas encore celui
        qu'elle a prouvé — la signature se vérifie à l'étape suivante.
        C'est suffisant : un attaquant qui déclare le bon `kid` échoue de
        toute façon à la signature, et un nonce présenté sous un autre
        `kid` n'est pas consommé.
        """


class DeviceStore(ABC):
    @abstractmethod
    def get(self, kid: bytes) -> DeviceRecord: ...

    @abstractmethod
    def update(self, record: DeviceRecord) -> None: ...


class InMemoryNonceStore(NonceStore):
    def __init__(self) -> None:
        self._nonces: dict[bytes, NonceRecord] = {}

    def issue(
        self,
        value: bytes,
        *,
        profile: Profile,
        kid: bytes,
        ttl_ms: int = 120_000,
        offline: bool = False,
    ) -> NonceRecord:
        # `profile` et `kid` sont sans défaut, délibérément : émettre un
        # nonce sans dire ce qu'on attend en retour, ni de qui, est la
        # faute que ces deux paramètres existent pour rendre impossible.
        rec = NonceRecord(
            value=value,
            issued_at_ms=int(time.time() * 1000),
            ttl_ms=ttl_ms,
            profile=profile,
            kid=kid,
            offline=offline,
        )
        self._nonces[value] = rec
        return rec

    def consume(self, nonce: bytes, now_ms: int, *, kid: bytes) -> NonceRecord:
        rec = self._nonces.get(nonce)
        if rec is None:
            raise UnknownNonce("nonce jamais émis par ce serveur")
        # Avant toute autre chose, et surtout avant de marquer consommé :
        # un nonce présenté par le mauvais appareil ressort intact.
        if rec.kid != kid:
            raise NonceDeviceMismatch("nonce émis pour un autre appareil")
        if rec.consumed_at_ms is not None:
            raise ReplayedNonce("nonce déjà consommé")
        if now_ms > rec.issued_at_ms + rec.ttl_ms:
            raise ExpiredNonce(
                f"nonce expiré depuis {now_ms - rec.issued_at_ms - rec.ttl_ms} ms"
            )
        rec.consumed_at_ms = now_ms
        return rec


class InMemoryDeviceStore(DeviceStore):
    def __init__(self) -> None:
        self._devices: dict[bytes, DeviceRecord] = {}

    def enroll(self, record: DeviceRecord) -> None:
        self._devices[record.kid] = record

    def get(self, kid: bytes) -> DeviceRecord:
        rec = self._devices.get(kid)
        if rec is None:
            raise UnknownKey("aucun appareil enrôlé pour ce kid")
        return rec

    def update(self, record: DeviceRecord) -> None:
        self._devices[record.kid] = record
