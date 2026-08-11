"""Serveur de développement — cible HTTP pour le spike natif.

Trois routes JSON donnent aux appareils réels la boucle complète :
enrôlement, émission de nonce, vérification. Ce module est un simple
câblage du `Verifier` : aucune décision de validité ne vit ici.

Il ne doit jamais servir en production : les états sont en mémoire, et
l'attestation par défaut est le substitut `NullAttestationVerifier` —
qui l'inscrit dans ses notes, pour que ce soit visible dans chaque
résultat.

L'enrôlement, lui, valide réellement une attestation App Attest quand
elle est fournie et qu'une application est configurée (phase D). Sans
attestation, la clé reste acceptée sur parole et la réponse le dit
(`attested: false`) — c'est le mode dégradé, pas le mode normal.

Les octets binaires transitent en base64 dans du JSON : moins compact
qu'un corps CBOR, mais lisible avec `curl` et sans dépendance — ce qui
suffit à un outil de développement.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .attestation import (
    AttestationVerifier,
    DeviceIntegrity,
    NullAttestationVerifier,
    verify_attestation,
)
from .errors import AttestationRejected, UnknownKey
from .model import Profile
from .store import DeviceRecord, InMemoryDeviceStore, InMemoryNonceStore
from .verifier import Verifier

DEFAULT_TTL_MS = 120_000

# Le spike natif produit des acquisitions : c'est le profil que le serveur
# de développement demande sauf mention contraire. Un vrai serveur tire
# cette valeur de la requête métier, jamais d'un défaut.
DEFAULT_PROFILE = Profile.CAPTURE


class BadRequest(Exception):
    """Requête HTTP invalide — faute du client, avant tout pipeline."""


def _require_map(body: Any) -> Mapping[str, Any]:
    if not isinstance(body, Mapping):
        raise BadRequest("objet JSON attendu")
    return body


def _b64_field(body: Mapping[str, Any], field: str) -> bytes:
    v = body.get(field)
    if not isinstance(v, str):
        raise BadRequest(f"champ {field} : chaîne base64 attendue")
    try:
        return base64.b64decode(v, validate=True)
    except binascii.Error as exc:
        raise BadRequest(f"champ {field} : base64 invalide") from exc


def _flag_field(body: Mapping[str, Any], field: str, default: bool) -> bool:
    v = body.get(field, default)
    if not isinstance(v, bool):
        raise BadRequest(f"champ {field} : booléen attendu")
    return v


def _uint_field(body: Mapping[str, Any], field: str, default: int) -> int:
    v = body.get(field, default)
    if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
        raise BadRequest(f"champ {field} : entier strictement positif attendu")
    return v


def _profile_field(body: Mapping[str, Any]) -> Profile:
    v = body.get("profile", DEFAULT_PROFILE.value)
    try:
        return Profile(v)
    except ValueError as exc:
        connus = ", ".join(sorted(p.value for p in Profile))
        raise BadRequest(f"champ profile : attendu parmi {connus}") from exc


class DevService:
    """Les trois opérations du serveur, découplées du transport HTTP."""

    def __init__(
        self,
        *,
        attestation: AttestationVerifier | None = None,
        app_attest: tuple[str, str, str] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        # (team_id, bundle_id, environnement) — données de compte, jamais
        # écrites dans le code. Sans elles, la route d'enrôlement refuse
        # une attestation plutôt que de faire semblant de la valider.
        self.app_attest = app_attest
        # Le certificat feuille d'App Attest ne vaut que quelques jours.
        # Pouvoir fixer l'horloge est donc nécessaire pour rejouer une
        # archive — et c'est le pendant du `now_ms` de `Verifier.verify`.
        self._now = now or (lambda: datetime.now(UTC))
        self.nonces = InMemoryNonceStore()
        self.devices = InMemoryDeviceStore()
        self.verifier = Verifier(
            nonce_store=self.nonces,
            device_store=self.devices,
            attestation=attestation or NullAttestationVerifier(DeviceIntegrity.STRONG),
        )

    def enroll(self, body: Mapping[str, Any]) -> dict[str, Any]:
        raw = _b64_field(body, "public_key_x962_b64")
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except ValueError as exc:
            raise BadRequest("clé publique X9.62 non compressée invalide") from exc

        platform = body.get("platform")
        if platform not in ("android", "ios"):
            raise BadRequest("champ platform : 'android' ou 'ios' attendu")

        # iOS : si une attestation App Attest accompagne l'enrôlement,
        # elle est réellement validée jusqu'à la racine Apple (phase D).
        # Sans elle, la clé reste acceptée sur parole — ce qu'un vrai
        # serveur ne fera jamais, et que la réponse signale.
        attestation_key: bytes | None = None
        attested = False
        if "attestation_b64" in body:
            if self.app_attest is None:
                raise BadRequest("aucune application App Attest configurée sur ce serveur")
            team_id, bundle_id, environment = self.app_attest
            try:
                enrollment = verify_attestation(
                    _b64_field(body, "attestation_b64"),
                    challenge=_b64_field(body, "challenge_b64"),
                    key_id=_b64_field(body, "key_id_b64"),
                    team_id=team_id,
                    bundle_id=bundle_id,
                    environment=environment,
                    now=self._now(),
                )
            except AttestationRejected as exc:
                raise BadRequest(f"attestation refusée : {exc.detail}") from exc
            attestation_key = enrollment.public_key_x962
            attested = True

        kid = hashlib.sha256(raw).digest()
        self.devices.enroll(
            DeviceRecord(
                kid=kid,
                public_key=public_key,
                platform=platform,
                hardware_backed=attested or _flag_field(body, "hardware_backed", True),
                attestation_key=attestation_key,
            )
        )
        return {
            "kid_b64": base64.b64encode(kid).decode(),
            "kid_hex": kid.hex(),
            "attested": attested,
        }

    def nonce(self, body: Mapping[str, Any]) -> dict[str, Any]:
        ttl_ms = _uint_field(body, "ttl_ms", DEFAULT_TTL_MS)
        offline = _flag_field(body, "offline", False)
        profile = _profile_field(body)

        # Un nonce est émis pour un appareil précis, et n'est utilisable
        # que par lui. On refuse d'en émettre pour un `kid` inconnu : cela
        # ne prouve rien mais évite d'entretenir un stock de nonces pour
        # des appareils qui n'existent pas.
        kid = _b64_field(body, "kid_b64")
        try:
            self.devices.get(kid)
        except UnknownKey as exc:
            raise BadRequest("kid inconnu : enrôler l'appareil d'abord") from exc

        value = os.urandom(16)
        self.nonces.issue(value, profile=profile, kid=kid, ttl_ms=ttl_ms, offline=offline)
        # Le profil est renvoyé : l'appareil doit inscrire exactement
        # celui-là dans son en-tête protégé, sinon l'enveloppe est rejetée.
        return {
            "nonce_b64": base64.b64encode(value).decode(),
            "ttl_ms": ttl_ms,
            "offline": offline,
            "profile": profile.value,
        }

    def verify(self, body: Mapping[str, Any]) -> dict[str, Any]:
        envelope = _b64_field(body, "envelope_b64")
        media = _b64_field(body, "media_b64") if "media_b64" in body else None
        return self.verifier.verify(envelope, media_bytes=media).to_dict()


def make_server(
    service: DevService, host: str = "127.0.0.1", port: int = 8765
) -> ThreadingHTTPServer:
    routes: dict[str, Callable[[Mapping[str, Any]], dict[str, Any]]] = {
        "/enroll": service.enroll,
        "/nonce": service.nonce,
        "/verify": service.verify,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            route = routes.get(self.path)
            if route is None:
                self._reply(404, {"error": f"route inconnue : {self.path}"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                body = _require_map(json.loads(raw) if raw else {})
                result = route(body)
            except (BadRequest, ValueError) as exc:
                # ValueError couvre JSONDecodeError mais aussi
                # UnicodeDecodeError : un corps non-UTF-8 sans BOM échoue
                # au décodage avant même l'analyse JSON.
                self._reply(400, {"error": str(exc)})
                return
            self._reply(200, result)

        def _reply(self, status: int, payload: Mapping[str, Any]) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Serveur de développement probative")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    server = make_server(DevService(), args.host, args.port)
    print(f"Serveur de développement : http://{args.host}:{server.server_address[1]}")
    print("ATTENTION : NullAttestationVerifier actif, aucune attestation réelle.")
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
