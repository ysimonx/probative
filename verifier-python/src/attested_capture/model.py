"""Modèle de données de l'enveloppe `ac/0.1`.

Le décodage est volontairement strict et défensif : l'enveloppe provient
d'un client considéré comme hostile. Toute donnée absente est `None`,
jamais une valeur par défaut plausible — un défaut plausible masquerait
une omission délibérée.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

from .errors import MalformedEnvelope

SPEC_SUPPORTED = {"ac/0.1"}

# Toutes les maps du format sont à clés entières (spec §2). L'alias évite
# de répéter l'annotation et rappelle que la valeur reste non validée tant
# qu'un `decode` ne l'a pas examinée.
CborMap = Mapping[int, Any]


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


class Level(str, Enum):
    STRONG = "STRONG"
    STANDARD = "STANDARD"
    DEGRADED = "DEGRADED"
    UNTRUSTED = "UNTRUSTED"
    REJECTED = "REJECTED"


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    F = "F"


class Property(str, Enum):
    ORIGIN = "origin"
    POSITION = "position"
    TIME = "time"
    INTEGRITY = "integrity"


# --- lecture défensive --------------------------------------------------
#
# Rien de ce que contient la charge utile n'a le type attendu tant qu'on
# ne l'a pas vérifié. Un champ mal typé doit produire un rejet motivé, et
# jamais l'une des deux issues suivantes : une exception qui remonte au
# serveur appelant, ou — plus grave — une valeur qui traverse le calcul
# des grades sans être remarquée.


def _map(v: Any, what: str) -> CborMap:
    if not isinstance(v, Mapping):
        raise MalformedEnvelope(f"{what} : map CBOR attendue")
    return v


def _seq(v: Any, what: str) -> Sequence[Any]:
    # `bytes` et `str` sont des Sequence : les exclure explicitement.
    if not isinstance(v, Sequence) or isinstance(v, (bytes, str)):
        raise MalformedEnvelope(f"{what} : tableau attendu")
    return v


def _req(m: CborMap, key: int, what: str) -> Any:
    if key not in m:
        raise MalformedEnvelope(f"champ obligatoire absent : {what} ({key})")
    return m[key]


def _as_text(v: Any, what: str) -> str:
    if not isinstance(v, str):
        raise MalformedEnvelope(f"{what} : chaîne attendue")
    return v


def _as_blob(v: Any, what: str) -> bytes:
    if not isinstance(v, bytes):
        raise MalformedEnvelope(f"{what} : chaîne d'octets attendue")
    return v


def _as_int(v: Any, what: str) -> int:
    # `bool` dérive de `int` en Python, mais pas en CBOR : un booléen là
    # où un entier est attendu reste une malformation.
    if not isinstance(v, int) or isinstance(v, bool):
        raise MalformedEnvelope(f"{what} : entier attendu")
    return v


def _as_uint(v: Any, what: str) -> int:
    n = _as_int(v, what)
    if n < 0:
        raise MalformedEnvelope(f"{what} : entier positif attendu")
    return n


def _as_real(v: Any, what: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise MalformedEnvelope(f"{what} : nombre attendu")
    return float(v)


def _as_flag(v: Any, what: str) -> bool:
    if not isinstance(v, bool):
        raise MalformedEnvelope(f"{what} : booléen attendu")
    return v


_T = TypeVar("_T")


def _get(m: CborMap, key: int, what: str, read: Callable[[Any, str], _T]) -> _T:
    """Champ obligatoire, dont le type est vérifié."""
    return read(_req(m, key, what), what)


def _opt(m: CborMap, key: int, what: str, read: Callable[[Any, str], _T]) -> _T | None:
    """Champ optionnel : absent vaut `None`, présent doit être du bon type."""
    v = m.get(key)
    return None if v is None else read(v, what)


@dataclass(frozen=True)
class Media:
    digest_alg: str
    digest: bytes
    mime: str
    length: int
    width: int
    height: int
    sign_latency_ms: int

    @classmethod
    def decode(cls, m: Any) -> Media:
        m = _map(m, "media")
        dims = _seq(_req(m, 5, "media.dimensions"), "media.dimensions")
        if len(dims) != 2:
            raise MalformedEnvelope("media.dimensions doit être [largeur, hauteur]")
        return cls(
            digest_alg=_get(m, 1, "media.digest_alg", _as_text),
            digest=_get(m, 2, "media.digest", _as_blob),
            mime=_get(m, 3, "media.mime", _as_text),
            length=_get(m, 4, "media.length", _as_uint),
            width=_as_uint(dims[0], "media.width"),
            height=_as_uint(dims[1], "media.height"),
            sign_latency_ms=_get(m, 6, "media.sign_latency_ms", _as_uint),
        )


@dataclass(frozen=True)
class Position:
    lat: float
    lon: float
    h_accuracy: float
    altitude: float | None
    v_accuracy: float | None
    provider: str
    fix_age_ms: int
    satellites: int | None

    @classmethod
    def decode(cls, m: Any) -> Position:
        m = _map(m, "position")
        return cls(
            lat=_get(m, 1, "position.lat", _as_real),
            lon=_get(m, 2, "position.lon", _as_real),
            h_accuracy=_get(m, 3, "position.h_accuracy", _as_real),
            altitude=_opt(m, 4, "position.altitude", _as_real),
            v_accuracy=_opt(m, 5, "position.v_accuracy", _as_real),
            provider=_get(m, 6, "position.provider", _as_text),
            fix_age_ms=_get(m, 7, "position.fix_age_ms", _as_uint),
            satellites=_opt(m, 8, "position.satellites", _as_uint),
        )


@dataclass(frozen=True)
class Timing:
    wall_ms: int
    monotonic_ms: int
    utc_offset_min: int
    auto_time: bool | None

    @classmethod
    def decode(cls, m: Any) -> Timing:
        m = _map(m, "timing")
        return cls(
            wall_ms=_get(m, 1, "timing.wall_ms", _as_uint),
            monotonic_ms=_get(m, 2, "timing.monotonic_ms", _as_uint),
            utc_offset_min=_get(m, 3, "timing.utc_offset_min", _as_int),
            auto_time=_opt(m, 4, "timing.auto_time", _as_flag),
        )


@dataclass(frozen=True)
class Posture:
    platform: Platform
    os_version: str
    app_version: str
    debugger: bool
    emulator: bool
    developer_mode: bool | None
    mock_location: bool | None
    suspicious_packages: list[str]
    jailbreak: bool | None

    @classmethod
    def decode(cls, m: Any) -> Posture:
        m = _map(m, "posture")
        raw = _get(m, 1, "posture.platform", _as_text)
        try:
            platform = Platform(raw)
        except ValueError as exc:
            raise MalformedEnvelope(f"plateforme inconnue : {raw!r}") from exc
        packages = _opt(m, 8, "posture.suspicious_packages", _seq)
        return cls(
            platform=platform,
            os_version=_get(m, 2, "posture.os_version", _as_text),
            app_version=_get(m, 3, "posture.app_version", _as_text),
            debugger=_get(m, 4, "posture.debugger", _as_flag),
            emulator=_get(m, 5, "posture.emulator", _as_flag),
            developer_mode=_opt(m, 6, "posture.developer_mode", _as_flag),
            mock_location=_opt(m, 7, "posture.mock_location", _as_flag),
            suspicious_packages=[
                _as_text(p, "posture.suspicious_packages") for p in (packages or ())
            ],
            jailbreak=_opt(m, 9, "posture.jailbreak", _as_flag),
        )


@dataclass(frozen=True)
class Claim:
    type: str
    sensor: str
    monotonic_ms: int
    value: Any

    @classmethod
    def decode(cls, m: Any) -> Claim:
        m = _map(m, "claim")
        return cls(
            type=_get(m, 1, "claim.type", _as_text),
            sensor=_get(m, 2, "claim.sensor", _as_text),
            monotonic_ms=_get(m, 3, "claim.monotonic_ms", _as_uint),
            # La mesure dépend du type de réclamation : elle reste non
            # typée ici, et chaque lecteur la valide pour son usage.
            value=_req(m, 4, "claim.value"),
        )


@dataclass(frozen=True)
class Freshness:
    kind: str
    token: bytes
    counter: int | None

    @classmethod
    def decode(cls, m: Any) -> Freshness:
        m = _map(m, "freshness")
        return cls(
            kind=_get(m, 1, "freshness.kind", _as_text),
            token=_get(m, 2, "freshness.token", _as_blob),
            counter=_opt(m, 3, "freshness.counter", _as_uint),
        )


@dataclass(frozen=True)
class CaptureClaims:
    nonce: bytes
    media: Media
    position: Position
    timing: Timing
    posture: Posture
    claims: list[Claim] = field(default_factory=list)
    prev_digest: bytes | None = None

    @classmethod
    def decode(cls, m: Any) -> CaptureClaims:
        # Point d'entrée de la charge utile : le type n'est pas garanti,
        # c'est ici qu'on l'établit avant tout accès.
        m = _map(m, "charge utile")
        raw_claims = _opt(m, 6, "corroboration", _seq)
        return cls(
            nonce=_get(m, 1, "nonce", _as_blob),
            media=Media.decode(_req(m, 2, "media")),
            position=Position.decode(_req(m, 3, "position")),
            timing=Timing.decode(_req(m, 4, "timing")),
            posture=Posture.decode(_req(m, 5, "posture")),
            claims=[Claim.decode(c) for c in (raw_claims or ())],
            prev_digest=_opt(m, 7, "chaînage", _as_blob),
        )

    def claim(self, type_: str) -> Claim | None:
        for c in self.claims:
            if c.type == type_:
                return c
        return None


@dataclass
class PropertyResult:
    grade: Grade
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    spec: str
    level: Level
    properties: dict[Property, PropertyResult]
    flags: list[str] = field(default_factory=list)
    level_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": self.spec,
            "level": self.level.value,
            "properties": {
                p.value: {
                    "grade": r.grade.value,
                    "evidence": r.evidence,
                    "notes": r.notes,
                }
                for p, r in self.properties.items()
            },
            "flags": self.flags,
            "level_reason": self.level_reason,
        }

    @classmethod
    def rejected(cls, code: str, detail: str = "") -> VerificationResult:
        return cls(
            spec="unknown",
            level=Level.REJECTED,
            properties={p: PropertyResult(Grade.F) for p in Property},
            flags=[code],
            level_reason=detail or code,
        )
