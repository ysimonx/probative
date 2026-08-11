"""Persistance requise par le vérificateur.

Trois états doivent survivre entre deux captures, et aucun ne peut être
confié au client :

  * les nonces émis, pour la règle R3 ;
  * les clés publiques enrôlées, pour la règle R2 ;
  * le compteur d'assertion et le dernier condensat d'enveloppe, pour
    l'ordonnancement.

Les implémentations mémoire ci-dessous servent aux tests. En production,
`NonceStore.consume` doit être atomique — un `UPDATE ... WHERE consumed_at
IS NULL` avec vérification du nombre de lignes affectées, jamais un
`SELECT` suivi d'un `UPDATE`, sous peine de rejeu par course.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from .errors import ExpiredNonce, ReplayedNonce, UnknownKey, UnknownNonce


@dataclass
class NonceRecord:
    value: bytes
    issued_at_ms: int
    ttl_ms: int
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


class NonceStore(ABC):
    @abstractmethod
    def consume(self, nonce: bytes, now_ms: int) -> NonceRecord: ...


class DeviceStore(ABC):
    @abstractmethod
    def get(self, kid: bytes) -> DeviceRecord: ...

    @abstractmethod
    def update(self, record: DeviceRecord) -> None: ...


class InMemoryNonceStore(NonceStore):
    def __init__(self) -> None:
        self._nonces: dict[bytes, NonceRecord] = {}

    def issue(self, value: bytes, ttl_ms: int = 120_000, offline: bool = False) -> NonceRecord:
        rec = NonceRecord(
            value=value,
            issued_at_ms=int(time.time() * 1000),
            ttl_ms=ttl_ms,
            offline=offline,
        )
        self._nonces[value] = rec
        return rec

    def consume(self, nonce: bytes, now_ms: int) -> NonceRecord:
        rec = self._nonces.get(nonce)
        if rec is None:
            raise UnknownNonce("nonce jamais émis par ce serveur")
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
