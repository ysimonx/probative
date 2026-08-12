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
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .attestation import (
    AttestationVerifier,
    CredentialsError,
    DeviceIntegrity,
    NullAttestationVerifier,
    PlayIntegrityVerifier,
    ServiceAccountKeyProvider,
    verify_attestation,
    verify_key_attestation,
)
from .errors import AttestationRejected, UnknownKey
from .grading import GradingPolicy, app_certificate_digest
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


def _b64_list_field(body: Mapping[str, Any], field: str) -> list[bytes]:
    """Liste de chaînes base64 — la chaîne de certificats, feuille en tête."""
    v = body.get(field)
    if not isinstance(v, list) or not v:
        raise BadRequest(f"champ {field} : liste base64 non vide attendue")
    sortie: list[bytes] = []
    for i, element in enumerate(v):
        if not isinstance(element, str):
            raise BadRequest(f"champ {field}[{i}] : chaîne base64 attendue")
        try:
            sortie.append(base64.b64decode(element, validate=True))
        except binascii.Error as exc:
            raise BadRequest(f"champ {field}[{i}] : base64 invalide") from exc
    return sortie


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
        policy: GradingPolicy | None = None,
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
            policy=policy or GradingPolicy(),
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
        hardware_backed: bool | None = None
        boot_verified: bool | None = None

        # Android : la chaîne d'attestation de clé est validée **jusqu'à la
        # racine publiée par Google**. Une chaîne cohérente se fabrique de
        # toutes pièces ; seule la confrontation à l'ancre prouve quelque
        # chose. Contrairement à App Attest, aucun appel réseau n'est
        # nécessaire : la puce a tout produit hors ligne.
        if "attestation_chain_b64" in body:
            if platform != "android":
                raise BadRequest(
                    "attestation_chain_b64 ne s'applique qu'à la plateforme android"
                )
            try:
                attestation = verify_key_attestation(
                    _b64_list_field(body, "attestation_chain_b64"),
                    challenge=_b64_field(body, "challenge_b64"),
                    now=self._now(),
                )
            except AttestationRejected as exc:
                raise BadRequest(f"attestation de clé refusée : {exc.detail}") from exc

            # Liaison décisive, et facile à omettre : une attestation valide
            # ne dit rien tant qu'on n'a pas établi qu'elle porte sur **la
            # clé qu'on enrôle**. Sans ce contrôle, une chaîne authentique
            # obtenue pour une autre clé ferait enrôler n'importe laquelle.
            if attestation.public_key_x962 != raw:
                raise BadRequest(
                    "la chaîne atteste une autre clé que celle présentée à l'enrôlement"
                )

            # Le niveau de sécurité vient de l'attestation, jamais d'un
            # drapeau déclaré par le client : c'est tout l'objet de la
            # manœuvre.
            hardware_backed = attestation.hardware_backed
            boot_verified = attestation.boot_verified
            attested = True

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
                # Ordre délibéré : ce qu'une attestation établit prime sur ce
                # que le client déclare. Le drapeau ne sert qu'au mode dégradé,
                # celui où aucune attestation n'accompagne l'enrôlement.
                hardware_backed=(
                    hardware_backed
                    if hardware_backed is not None
                    else attested or _flag_field(body, "hardware_backed", True)
                ),
                boot_verified_at_enrollment=boot_verified,
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


ENV_TRUSTED_CERTS = "PROBATIVE_TRUSTED_APP_CERTS"
ENV_ANDROID_PACKAGE = "PROBATIVE_ANDROID_PACKAGE"
ENV_SERVICE_ACCOUNT = "PROBATIVE_SERVICE_ACCOUNT"


def _load_dotenv(chemin: Path) -> list[str]:
    """Charge un `.env` **sans écraser** l'environnement réel.

    Quinze lignes plutôt qu'une dépendance : `python-dotenv` ferait passer le
    vérificateur de deux à trois paquets pour lire des `clé=valeur`
    (ADR-0001, surface minimale).

    L'environnement réel prime, comme le veut l'usage : un déploiement ou une
    chaîne d'intégration doit pouvoir surcharger le fichier sans l'éditer.

    **Seul le point d'entrée applicatif appelle ceci.** Une bibliothèque qui
    lit un fichier ambiant devient impossible à tester et surprend son
    intégrateur ; `GradingPolicy` et `DevService` ne connaissent que des
    valeurs qu'on leur passe.
    """
    if not chemin.is_file():
        return []
    charges: list[str] = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#") or "=" not in ligne:
            continue
        cle, _, valeur = ligne.partition("=")
        cle = cle.strip()
        valeur = valeur.strip().strip("\"'")
        if cle and cle not in os.environ:
            os.environ[cle] = valeur
            charges.append(cle)
    return charges


def _policy_from_env() -> GradingPolicy:
    """Politique de déploiement lue dans l'environnement.

    `PROBATIVE_TRUSTED_APP_CERTS` porte les empreintes SHA-256 des
    certificats de signature que **ce déploiement** reconnaît comme siens,
    séparées par des virgules, dans la forme hexadécimale qu'affichent les
    consoles :

        PROBATIVE_TRUSTED_APP_CERTS="C9:35:3E:DA:…,AB:CD:…"

    Cette valeur est **propre à chaque déploiement** : elle dépend du compte
    Play Console qui publie l'application. Elle n'a donc rien à faire dans le
    dépôt, et le défaut — aucune empreinte — laisse le comportement d'origine,
    où un binaire non reconnu par le magasin tombe sur `unrecognized_app_grade`.

    L'empreinte à fournir est celle du **certificat de déploiement**, que la
    Play Console ne montre pas sur sa page mais livre dans l'archive de
    « Télécharger des certificats ». Voir `docs/play-integrity-service-account.md`
    §8.2 : les deux empreintes mises en évidence par la console ne conviennent
    pas, et l'échec serait silencieux. La procédure complète, de l'archive à
    cette variable, est en §8.2 bis.
    """
    brut = os.environ.get(ENV_TRUSTED_CERTS, "").strip()
    if not brut:
        return GradingPolicy()
    empreintes = tuple(
        app_certificate_digest(morceau)
        for morceau in brut.replace(";", ",").split(",")
        if morceau.strip()
    )
    return GradingPolicy(trusted_app_certificates=empreintes)


def _attestation_from_env() -> tuple[AttestationVerifier | None, str]:
    """Vérificateur d'attestation réel, si l'environnement le permet.

    Rend `(None, motif)` quand la configuration est absente — le substitut
    prend alors le relais, et le motif est affiché au démarrage. **Ne jamais
    échouer silencieusement vers le substitut** : une campagne qui croit
    valider une attestation réelle alors qu'elle n'en valide aucune est
    exactement le no-op que ce dépôt traque.

    Deux valeurs suffisent, toutes deux propres au déploiement :

        PROBATIVE_ANDROID_PACKAGE=org.probative.demo
        PROBATIVE_SERVICE_ACCOUNT=./service-account.json

    Le chemin pointe vers la clé du compte de service, qui vit **hors du
    dépôt** (voir `install.sh`). C'est le seul secret de la chaîne, et il
    n'entre pas dans le `.env`, qui n'en contient aucun.
    """
    paquet = os.environ.get(ENV_ANDROID_PACKAGE, "").strip()
    cle = os.environ.get(ENV_SERVICE_ACCOUNT, "").strip()
    if not paquet or not cle:
        manquantes = [
            nom
            for nom, valeur in ((ENV_ANDROID_PACKAGE, paquet), (ENV_SERVICE_ACCOUNT, cle))
            if not valeur
        ]
        return None, f"{', '.join(manquantes)} absent(es)"

    chemin = Path(cle).expanduser()
    if not chemin.is_file():
        # Un chemin fourni mais introuvable est une faute de configuration,
        # pas une absence : on le dit, plutôt que de retomber sur le substitut.
        raise SystemExit(f"{ENV_SERVICE_ACCOUNT} : fichier introuvable — {chemin}")

    try:
        identifiants = ServiceAccountKeyProvider(chemin)
    except CredentialsError as exc:
        raise SystemExit(f"{ENV_SERVICE_ACCOUNT} : {exc}") from exc

    return PlayIntegrityVerifier(package_name=paquet, credentials=identifiants), ""


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Serveur de développement probative")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--env-file",
        default=".env",
        help="fichier de configuration ; l'environnement réel prime sur lui",
    )
    args = parser.parse_args(argv)

    charges = _load_dotenv(Path(args.env_file))
    if charges:
        print(f"{args.env_file} : {', '.join(charges)}")

    try:
        policy = _policy_from_env()
    except ValueError as exc:
        # Une empreinte mal formée doit arrêter le serveur, jamais le laisser
        # démarrer avec une liste silencieusement incomplète : le symptôme
        # serait un binaire légitime traité comme reconditionné.
        raise SystemExit(f"{ENV_TRUSTED_CERTS} : {exc}") from exc

    attestation, motif = _attestation_from_env()

    server = make_server(
        DevService(attestation=attestation, policy=policy), args.host, args.port
    )
    print(f"Serveur de développement : http://{args.host}:{server.server_address[1]}")
    if attestation is None:
        print(f"ATTENTION : NullAttestationVerifier actif ({motif}).")
        print("  Aucune attestation réelle n'est validée — voir .env.example.")
    else:
        print(
            f"PlayIntegrityVerifier actif sur "
            f"{os.environ[ENV_ANDROID_PACKAGE]} — attestation réelle."
        )
    if policy.trusted_app_certificates:
        print(
            f"{len(policy.trusted_app_certificates)} empreinte(s) de certificat "
            f"déclarée(s) via {ENV_TRUSTED_CERTS}"
        )
    else:
        print(
            f"Aucune empreinte déclarée ({ENV_TRUSTED_CERTS} vide) : un binaire non "
            "reconnu par le magasin sera noté sans distinction d'origine."
        )
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
