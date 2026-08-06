"""Modèle de données de l'enveloppe `ac/0.1`.

Le décodage est volontairement strict et défensif : l'enveloppe provient
d'un client considéré comme hostile. Toute donnée absente est `None`,
jamais une valeur par défaut plausible — un défaut plausible masquerait
une omission délibérée.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .errors import MalformedEnvelope

SPEC_SUPPORTED = {"ac/0.1"}


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


def _req(m: Mapping, key: int, what: str) -> Any:
    if key not in m:
        raise MalformedEnvelope(f"champ obligatoire absent : {what} ({key})")
    return m[key]


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
    def decode(cls, m: Mapping) -> "Media":
        dims = _req(m, 5, "media.dimensions")
        if not isinstance(dims, Sequence) or isinstance(dims, (bytes, str)) or len(dims) != 2:
            raise MalformedEnvelope("media.dimensions doit être [largeur, hauteur]")
        return cls(
            digest_alg=_req(m, 1, "media.digest_alg"),
            digest=_req(m, 2, "media.digest"),
            mime=_req(m, 3, "media.mime"),
            length=_req(m, 4, "media.length"),
            width=dims[0],
            height=dims[1],
            sign_latency_ms=_req(m, 6, "media.sign_latency_ms"),
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
    def decode(cls, m: Mapping) -> "Position":
        return cls(
            lat=_req(m, 1, "position.lat"),
            lon=_req(m, 2, "position.lon"),
            h_accuracy=_req(m, 3, "position.h_accuracy"),
            altitude=m.get(4),
            v_accuracy=m.get(5),
            provider=_req(m, 6, "position.provider"),
            fix_age_ms=_req(m, 7, "position.fix_age_ms"),
            satellites=m.get(8),
        )


@dataclass(frozen=True)
class Timing:
    wall_ms: int
    monotonic_ms: int
    utc_offset_min: int
    auto_time: bool | None

    @classmethod
    def decode(cls, m: Mapping) -> "Timing":
        return cls(
            wall_ms=_req(m, 1, "timing.wall_ms"),
            monotonic_ms=_req(m, 2, "timing.monotonic_ms"),
            utc_offset_min=_req(m, 3, "timing.utc_offset_min"),
            auto_time=m.get(4),
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
    def decode(cls, m: Mapping) -> "Posture":
        raw = _req(m, 1, "posture.platform")
        try:
            platform = Platform(raw)
        except ValueError as exc:
            raise MalformedEnvelope(f"plateforme inconnue : {raw!r}") from exc
        return cls(
            platform=platform,
            os_version=_req(m, 2, "posture.os_version"),
            app_version=_req(m, 3, "posture.app_version"),
            debugger=_req(m, 4, "posture.debugger"),
            emulator=_req(m, 5, "posture.emulator"),
            developer_mode=m.get(6),
            mock_location=m.get(7),
            suspicious_packages=list(m.get(8) or []),
            jailbreak=m.get(9),
        )


@dataclass(frozen=True)
class Claim:
    type: str
    sensor: str
    monotonic_ms: int
    value: Any

    @classmethod
    def decode(cls, m: Mapping) -> "Claim":
        return cls(
            type=_req(m, 1, "claim.type"),
            sensor=_req(m, 2, "claim.sensor"),
            monotonic_ms=_req(m, 3, "claim.monotonic_ms"),
            value=_req(m, 4, "claim.value"),
        )


@dataclass(frozen=True)
class Freshness:
    kind: str
    token: bytes
    counter: int | None

    @classmethod
    def decode(cls, m: Mapping) -> "Freshness":
        return cls(
            kind=_req(m, 1, "freshness.kind"),
            token=_req(m, 2, "freshness.token"),
            counter=m.get(3),
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
    def decode(cls, m: Mapping) -> "CaptureClaims":
        if not isinstance(m, Mapping):
            raise MalformedEnvelope("la charge utile n'est pas une map CBOR")
        return cls(
            nonce=_req(m, 1, "nonce"),
            media=Media.decode(_req(m, 2, "media")),
            position=Position.decode(_req(m, 3, "position")),
            timing=Timing.decode(_req(m, 4, "timing")),
            posture=Posture.decode(_req(m, 5, "posture")),
            claims=[Claim.decode(c) for c in (m.get(6) or [])],
            prev_digest=m.get(7),
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

    def to_dict(self) -> dict:
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
    def rejected(cls, code: str, detail: str = "") -> "VerificationResult":
        return cls(
            spec="unknown",
            level=Level.REJECTED,
            properties={p: PropertyResult(Grade.F) for p in Property},
            flags=[code],
            level_reason=detail or code,
        )
