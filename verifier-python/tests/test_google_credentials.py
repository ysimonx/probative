"""Couture d'authentification Google (ADR-0006), éprouvée hors ligne.

Aucun appel réseau, aucune clé réelle : la clé RSA est engendrée à
l'exécution et ne quitte jamais le répertoire temporaire du test. Le
serveur de jetons de Google est remplacé par un bouchon qui capture le JWT
émis — c'est lui l'objet du test, puisque c'est la seule chose que ce
module produise vraiment.

Ce que ces tests garantissent tient en une phrase : le JWT que nous
signons est celui que Google attend, et un échec se voit.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from probative.attestation.google_credentials import (
    SCOPE,
    CredentialsError,
    ServiceAccountKeyProvider,
)

TOKEN_URI = "https://oauth2.googleapis.com/token"
EMAIL = "probative-verifier@probative.iam.gserviceaccount.com"


def _write_key_file(tmp_path: Path, *, key: Any = None, **surcharges: Any) -> Path:
    """Écrit un fichier de compte de service plausible, clé engendrée à la volée."""
    key = key if key is not None else rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    contenu: dict[str, Any] = {
        "type": "service_account",
        "project_id": "probative",
        "client_email": EMAIL,
        "token_uri": TOKEN_URI,
        "private_key": pem,
    }
    contenu.update(surcharges)
    # Une surcharge à None retire le champ : c'est ainsi qu'on fabrique un
    # fichier incomplet sans dupliquer tout le gabarit.
    contenu = {c: v for c, v in contenu.items() if v is not None}
    chemin = tmp_path / "service-account.json"
    chemin.write_text(json.dumps(contenu))
    return chemin


class _Corps:
    """Objet lisible, ce qu'attendent `urlopen` et `HTTPError` pour leur corps."""

    def __init__(self, contenu: bytes) -> None:
        self._contenu = contenu

    def read(self) -> bytes:
        return self._contenu

    def close(self) -> None:
        """`HTTPError` referme le corps qu'on lui passe : sans ceci, pytest
        signale une exception ignorée dans le destructeur."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _reponse(corps: dict[str, Any]) -> _Corps:
    return _Corps(json.dumps(corps).encode())


@pytest.fixture
def bouchon(monkeypatch: pytest.MonkeyPatch) -> list[urllib.request.Request]:
    """Remplace le serveur de jetons et conserve les requêtes émises."""
    recues: list[urllib.request.Request] = []

    def _urlopen(request: urllib.request.Request, timeout: int = 0) -> _Corps:
        recues.append(request)
        return _reponse({"access_token": f"jeton-{len(recues)}", "expires_in": 3600})

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    return recues


def _assertion(request: urllib.request.Request) -> str:
    """Extrait le JWT du corps formulaire posté au serveur de jetons."""
    assert request.data is not None
    champs = urllib.parse.parse_qs(request.data.decode())
    return champs["assertion"][0]


def _segments(request: urllib.request.Request) -> tuple[Any, Any, bytes, bytes]:
    entete_b64, claims_b64, signature_b64 = _assertion(request).split(".")
    return (
        json.loads(_unb64(entete_b64)),
        json.loads(_unb64(claims_b64)),
        _unb64(signature_b64),
        f"{entete_b64}.{claims_b64}".encode(),
    )


def _unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def test_jwt_porte_les_revendications_attendues(
    tmp_path: Path, bouchon: list[urllib.request.Request]
) -> None:
    jeton = ServiceAccountKeyProvider(_write_key_file(tmp_path)).access_token()

    assert jeton == "jeton-1"
    entete, claims, _, _ = _segments(bouchon[0])
    assert entete == {"alg": "RS256", "typ": "JWT"}
    assert claims["iss"] == EMAIL
    assert claims["aud"] == TOKEN_URI
    assert claims["scope"] == SCOPE
    # Une heure au plus : au-delà, Google refuse l'assertion.
    assert claims["exp"] - claims["iat"] == 3_600


def test_signature_du_jwt_verifiable_par_la_cle_publique(
    tmp_path: Path, bouchon: list[urllib.request.Request]
) -> None:
    """Le cœur du module : si cette vérification passe, Google l'acceptera."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ServiceAccountKeyProvider(_write_key_file(tmp_path, key=key)).access_token()

    _, _, signature, signe = _segments(bouchon[0])
    key.public_key().verify(signature, signe, padding.PKCS1v15(), hashes.SHA256())


def test_segments_en_base64url_sans_bourrage(
    tmp_path: Path, bouchon: list[urllib.request.Request]
) -> None:
    """Un `=` de bourrage, un `+` ou un `/` feraient rejeter l'assertion."""
    ServiceAccountKeyProvider(_write_key_file(tmp_path)).access_token()

    assertion = _assertion(bouchon[0])
    assert "=" not in assertion
    assert "+" not in assertion
    assert "/" not in assertion


def test_le_jeton_est_mis_en_cache(
    tmp_path: Path, bouchon: list[urllib.request.Request]
) -> None:
    provider = ServiceAccountKeyProvider(_write_key_file(tmp_path))

    assert provider.access_token() == provider.access_token()
    assert len(bouchon) == 1, "le second appel a repassé un aller-retour réseau"


def test_le_cache_expire(
    tmp_path: Path, bouchon: list[urllib.request.Request], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un jeton périmé doit être renouvelé, sinon l'appel suivant part en 401."""
    horloge = [1_000_000.0]
    monkeypatch.setattr(
        "probative.attestation.google_credentials.time.time", lambda: horloge[0]
    )
    provider = ServiceAccountKeyProvider(_write_key_file(tmp_path))
    assert provider.access_token() == "jeton-1"

    horloge[0] += 3_600  # au-delà de la durée de vie moins la marge
    assert provider.access_token() == "jeton-2"
    assert len(bouchon) == 2


def test_fichier_absent(tmp_path: Path) -> None:
    with pytest.raises(CredentialsError, match="illisible"):
        ServiceAccountKeyProvider(tmp_path / "inexistant.json")


def test_champ_manquant(tmp_path: Path) -> None:
    with pytest.raises(CredentialsError, match="champ absent"):
        ServiceAccountKeyProvider(_write_key_file(tmp_path, client_email=None))


def test_cle_non_rsa_refusee(tmp_path: Path) -> None:
    """Google n'accepte que RS256 : une clé EC doit échouer ici, pas en vol."""
    ec_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(CredentialsError, match="RSA attendu"):
        ServiceAccountKeyProvider(_write_key_file(tmp_path, key=ec_key))


def test_refus_du_serveur_remonte_le_motif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`invalid_grant` sur une horloge décalée est indiagnosticable sans le corps."""

    def _urlopen(*_: object, **__: object) -> _Corps:
        raise urllib.error.HTTPError(
            TOKEN_URI, 400, "Bad Request", {}, _Corps(b'{"error":"invalid_grant"}')
        )

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    with pytest.raises(CredentialsError, match="invalid_grant"):
        ServiceAccountKeyProvider(_write_key_file(tmp_path)).access_token()


def test_reponse_sans_access_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _reponse({"expires_in": 3600})
    )
    with pytest.raises(CredentialsError, match="sans access_token"):
        ServiceAccountKeyProvider(_write_key_file(tmp_path)).access_token()


def test_serveur_injoignable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _urlopen(*_: object, **__: object) -> _Corps:
        raise urllib.error.URLError("réseau absent")

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    with pytest.raises(CredentialsError, match="injoignable"):
        ServiceAccountKeyProvider(_write_key_file(tmp_path)).access_token()
