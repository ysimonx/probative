"""Serveur de développement : boucle complète et câblage d'erreurs.

Le serveur n'ajoute aucune décision au pipeline : ces tests vérifient
le câblage — enrôlement, émission de nonce, transport du résultat — et
que les rejets du vérificateur traversent intacts, avec leur code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
from factory import make_payload, new_key, sign_envelope

from probative.devserver import BadRequest, DevService, make_server

MEDIA = b"image-de-test"
MEDIA_DIGEST = hashlib.sha256(MEDIA).digest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _public_x962(key: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


# --- Niveau service : validation des entrées ------------------------------


def test_enrolement_cle_invalide():
    with pytest.raises(BadRequest):
        DevService().enroll({"public_key_x962_b64": _b64(b"pas une cle"), "platform": "android"})


def test_enrolement_plateforme_inconnue():
    body = {"public_key_x962_b64": _b64(_public_x962(new_key())), "platform": "windows"}
    with pytest.raises(BadRequest):
        DevService().enroll(body)


def test_champ_base64_invalide():
    with pytest.raises(BadRequest):
        DevService().verify({"envelope_b64": "%%%"})


# --- Niveau HTTP : boucle complète ----------------------------------------


@pytest.fixture
def server_url() -> Iterator[str]:
    server = make_server(DevService(), "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _post(url: str, path: str, body: dict[str, Any] | None) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        url + path,
        data=json.dumps(body).encode() if body is not None else b"",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_boucle_complete_par_http(server_url):
    key = new_key()

    status, enrolled = _post(
        server_url,
        "/enroll",
        {"public_key_x962_b64": _b64(_public_x962(key)), "platform": "android"},
    )
    assert status == 200
    assert enrolled["kid_hex"] == hashlib.sha256(_public_x962(key)).hexdigest()

    status, issued = _post(server_url, "/nonce", None)
    assert status == 200
    nonce = base64.b64decode(issued["nonce_b64"])

    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    envelope = sign_envelope(key, payload, nonce=nonce)
    status, result = _post(
        server_url,
        "/verify",
        {"envelope_b64": _b64(envelope), "media_b64": _b64(MEDIA)},
    )
    assert status == 200
    assert result["level"] in ("STANDARD", "STRONG"), result
    assert result["level_reason"]

    # Rejeu : le même nonce est refusé, avec le code attendu (R3).
    status, replay = _post(server_url, "/verify", {"envelope_b64": _b64(envelope)})
    assert status == 200
    assert replay["level"] == "REJECTED"
    assert "REPLAYED_NONCE" in replay["flags"]


def test_nonce_jamais_emis_rejete(server_url):
    key = new_key()
    _post(
        server_url,
        "/enroll",
        {"public_key_x962_b64": _b64(_public_x962(key)), "platform": "android"},
    )
    nonce = os.urandom(16)
    envelope = sign_envelope(key, make_payload(nonce=nonce), nonce=nonce)

    status, result = _post(server_url, "/verify", {"envelope_b64": _b64(envelope)})
    assert status == 200
    assert result["level"] == "REJECTED"
    assert "UNKNOWN_NONCE" in result["flags"]


def test_cle_non_enrolee_rejetee(server_url):
    key = new_key()
    status, issued = _post(server_url, "/nonce", None)
    nonce = base64.b64decode(issued["nonce_b64"])
    envelope = sign_envelope(key, make_payload(nonce=nonce), nonce=nonce)

    status, result = _post(server_url, "/verify", {"envelope_b64": _b64(envelope)})
    assert status == 200
    assert result["level"] == "REJECTED"
    assert "UNKNOWN_KEY" in result["flags"]


def test_erreurs_de_transport(server_url):
    status, body = _post(server_url, "/inconnue", None)
    assert status == 404

    req = urllib.request.Request(
        server_url + "/verify", data=b"pas du json", method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400

    status, body = _post(server_url, "/verify", {})
    assert status == 400
    assert "envelope_b64" in body["error"]
