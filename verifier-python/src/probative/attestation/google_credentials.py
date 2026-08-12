"""Obtention d'un jeton d'accès Google, et la couture qui la rend remplaçable.

Ce module ne vérifie rien. Il ne produit qu'un jeton d'accès OAuth 2.0 pour
appeler `decodeIntegrityToken` — de l'authentification **sortante**, jamais de
la validation d'entrée hostile.

Cette distinction est ce qui autorise l'implémentation par défaut à signer son
JWT elle-même plutôt que d'ajouter huit paquets à un vérificateur qui n'en
compte que deux. Un défaut de signature ici fait rejeter l'appel par Google, au
premier essai et bruyamment ; il n'ouvre aucune porte. Écrire soi-même la
*vérification* d'une entrée hostile serait une tout autre affaire.

**La couture prime sur l'implémentation.** Un déploiement sur Google Cloud
n'utilise pas de fichier de clé — il passe par la fédération d'identité de
charge de travail, ce que `google-auth` gère et ce que ce module ne fera
jamais. `AccessTokenProvider` existe pour qu'un tel déploiement injecte le
sien sans que le dépôt impose sa dépendance à tous les autres, ni au
déploiement iOS qui n'appellera jamais Play Integrity.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SCOPE = "https://www.googleapis.com/auth/playintegrity"

# Le JWT d'authentification vaut une heure au plus (RFC 7523 et contrainte
# Google). On demande moins, et on renouvelle avant l'échéance : une horloge
# serveur légèrement en avance ferait rejeter un jeton encore « valide » ici.
_ASSERTION_LIFETIME_S = 3_600
_REFRESH_MARGIN_S = 60


class CredentialsError(Exception):
    """Identifiants illisibles, ou refus du serveur de jetons de Google."""


class AccessTokenProvider(Protocol):
    """Fournit un jeton d'accès portant la portée `playintegrity`.

    Implémenté par `ServiceAccountKeyProvider` pour le cas du fichier de clé.
    Un déploiement Google Cloud fournit le sien, par exemple :

        from google.auth.transport.requests import Request
        from google.oauth2 import service_account

        class GoogleAuthProvider:
            def __init__(self, creds): self._creds = creds
            def access_token(self) -> str:
                if not self._creds.valid:
                    self._creds.refresh(Request())
                return self._creds.token
    """

    def access_token(self) -> str: ...


@dataclass
class _CachedToken:
    value: str
    expires_at: float


class ServiceAccountKeyProvider:
    """Flux JWT-bearer (RFC 7523) à partir d'un fichier de clé JSON.

    Implémentation par défaut, sans dépendance nouvelle : `cryptography` sait
    déjà signer en RSA-SHA256, et `urllib` est dans la bibliothèque standard.
    """

    def __init__(self, key_path: str | Path, *, scope: str = SCOPE) -> None:
        self._scope = scope
        self._cached: _CachedToken | None = None

        try:
            raw = json.loads(Path(key_path).read_bytes())
        except (OSError, ValueError) as exc:
            raise CredentialsError(f"fichier de clé illisible : {exc}") from exc

        # Décodage défensif : ce fichier vient du poste d'exploitation, pas
        # d'un attaquant, mais un champ manquant doit se voir ici plutôt que
        # de produire un JWT incompréhensible pour Google.
        try:
            self._client_email = str(raw["client_email"])
            self._token_uri = str(raw["token_uri"])
            private_key = str(raw["private_key"])
        except KeyError as exc:
            raise CredentialsError(f"champ absent du fichier de clé : {exc}") from exc

        key = serialization.load_pem_private_key(private_key.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise CredentialsError("clé de compte de service : RSA attendu")
        self._key = key

    def access_token(self) -> str:
        now = time.time()
        if self._cached is not None and now < self._cached.expires_at:
            return self._cached.value

        assertion = self._signed_assertion(now)
        payload = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            }
        ).encode()

        request = urllib.request.Request(
            self._token_uri,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            # Le corps porte le motif exact (`invalid_grant` sur une horloge
            # décalée, par exemple) ; le code seul n'aiderait personne.
            raise CredentialsError(
                f"jeton d'accès refusé ({exc.code}) : {exc.read().decode(errors='replace')}"
            ) from exc
        except (urllib.error.URLError, ValueError, TimeoutError) as exc:
            raise CredentialsError(f"serveur de jetons injoignable : {exc}") from exc

        token = body.get("access_token")
        if not isinstance(token, str):
            raise CredentialsError("réponse sans access_token")

        lifetime = body.get("expires_in", _ASSERTION_LIFETIME_S)
        lifetime = lifetime if isinstance(lifetime, int) else _ASSERTION_LIFETIME_S
        self._cached = _CachedToken(token, now + lifetime - _REFRESH_MARGIN_S)
        return token

    def _signed_assertion(self, now: float) -> str:
        issued = int(now)
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._client_email,
            "scope": self._scope,
            "aud": self._token_uri,
            "iat": issued,
            "exp": issued + _ASSERTION_LIFETIME_S,
        }
        signing_input = _b64(header).encode() + b"." + _b64(claims).encode()
        signature = self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return (signing_input + b"." + _b64url(signature)).decode()


def _b64(obj: Mapping[str, object]) -> str:
    """Segment JWT : JSON compact, base64url **sans bourrage**."""
    compact = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return _b64url(compact).decode()


def _b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")
