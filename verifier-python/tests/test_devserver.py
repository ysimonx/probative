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
from datetime import UTC, datetime
from pathlib import Path
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


def test_nonce_profil_inconnu_refuse():
    """Émettre un nonce pour un profil qu'on ne saura pas juger n'a pas de sens."""
    with pytest.raises(BadRequest):
        DevService().nonce({"profile": "profil-de-demain", "kid_b64": _b64(b"x" * 32)})


def test_nonce_profil_noyau_demandable():
    service = DevService()
    enrolled = service.enroll(
        {"public_key_x962_b64": _b64(_public_x962(new_key())), "platform": "android"}
    )
    issued = service.nonce({"profile": "core", "kid_b64": enrolled["kid_b64"]})
    assert issued["profile"] == "core"


# --- Enrôlement attesté — phase D -----------------------------------------


def _app_attest_vector() -> dict:
    path = Path(__file__).parent / "device-vectors" / "appattest-c3-iphone16.json"
    return json.loads(path.read_text())


def _enroll_body(vector: dict) -> dict:
    return {
        "public_key_x962_b64": vector["signingKey"]["publicKeyX962"],
        "platform": "ios",
        "attestation_b64": vector["enrollment"]["attestation"],
        "challenge_b64": base64.b64encode(
            base64.b64decode(vector["enrollment"]["challenge"])
        ).decode(),
        "key_id_b64": vector["keyId"],
    }


def _attested_service(vector: dict) -> DevService:
    # Le certificat feuille d'App Attest ne vaut que trois jours. Sans
    # horloge fixée, ce test cesserait de passer un beau matin sans
    # qu'aucune ligne de code n'ait changé — et on chercherait longtemps.
    return DevService(
        app_attest=("9SGKL7VUD3", vector["app"]["bundleId"], "development"),
        now=lambda: datetime(2026, 8, 11, 12, tzinfo=UTC),
    )


def test_enrolement_atteste_retient_la_cle_app_attest():
    """L'enrôlement ne prend plus la clé sur parole quand une attestation vient."""
    vector = _app_attest_vector()
    service = _attested_service(vector)

    result = service.enroll(_enroll_body(vector))

    assert result["attested"] is True
    kid = base64.b64decode(result["kid_b64"])
    record = service.devices.get(kid)
    assert record.attestation_key is not None
    assert record.attestation_key != base64.b64decode(vector["signingKey"]["publicKeyX962"]), (
        "la clé App Attest et la clé de signature sont deux clés distinctes"
    )
    assert hashlib.sha256(record.attestation_key).digest() == base64.b64decode(vector["keyId"])


def test_enrolement_atteste_refuse_un_defi_qui_nest_pas_le_sien():
    """Rejouer une attestation obtenue ailleurs, contre un autre défi."""
    vector = _app_attest_vector()
    body = _enroll_body(vector) | {"challenge_b64": _b64(b"un-defi-qui-nest-pas-le-notre")}

    with pytest.raises(BadRequest, match="attestation refusée"):
        _attested_service(vector).enroll(body)


def test_enrolement_atteste_expire_refuse():
    """Hors période de validité, l'attestation ne vaut plus rien."""
    vector = _app_attest_vector()
    service = DevService(
        app_attest=("9SGKL7VUD3", vector["app"]["bundleId"], "development"),
        now=lambda: datetime(2027, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(BadRequest, match="attestation refusée"):
        service.enroll(_enroll_body(vector))


def test_enrolement_sans_application_configuree_refuse_une_attestation():
    """Mieux vaut refuser que faire semblant de valider."""
    vector = _app_attest_vector()
    with pytest.raises(BadRequest, match="App Attest"):
        DevService().enroll(_enroll_body(vector))


def test_enrolement_sans_attestation_reste_accepte_sur_parole():
    """Le mode dégradé du serveur de développement, explicitement signalé."""
    result = DevService().enroll(
        {"public_key_x962_b64": _b64(_public_x962(new_key())), "platform": "ios"}
    )
    assert result["attested"] is False


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

    status, issued = _post(server_url, "/nonce", {"kid_b64": enrolled["kid_b64"]})
    assert status == 200
    nonce = base64.b64decode(issued["nonce_b64"])
    # Le profil demandé fait partie de la réponse : l'appareil doit
    # l'inscrire tel quel dans son en-tête protégé.
    assert issued["profile"] == "capture"

    payload = make_payload(nonce=nonce, media_digest=MEDIA_DIGEST)
    envelope = sign_envelope(key, payload, nonce=nonce)
    status, result = _post(
        server_url,
        "/verify",
        {"envelope_b64": _b64(envelope), "media_b64": _b64(MEDIA)},
    )
    assert status == 200
    assert result["level"] in ("STANDARD", "STRONG"), result
    assert result["profile"] == "capture"
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


def test_nonce_refuse_pour_un_kid_inconnu(server_url):
    """La route d'émission n'entretient pas de stock pour des appareils
    qui n'existent pas — premier verrou contre la moisson."""
    status, body = _post(server_url, "/nonce", {"kid_b64": _b64(os.urandom(32))})
    assert status == 400
    assert "kid inconnu" in body["error"]


def test_nonce_dun_autre_appareil_rejete_par_http(server_url):
    """Deux appareils enrôlés, le second essaie le nonce du premier."""
    premier, second = new_key(), new_key()
    kids = []
    for k in (premier, second):
        _, enrolled = _post(
            server_url,
            "/enroll",
            {"public_key_x962_b64": _b64(_public_x962(k)), "platform": "android"},
        )
        kids.append(enrolled["kid_b64"])

    _, issued = _post(server_url, "/nonce", {"kid_b64": kids[0]})
    nonce = base64.b64decode(issued["nonce_b64"])
    envelope = sign_envelope(second, make_payload(nonce=nonce), nonce=nonce)

    status, result = _post(server_url, "/verify", {"envelope_b64": _b64(envelope)})
    assert status == 200
    assert result["level"] == "REJECTED"
    assert "NONCE_DEVICE_MISMATCH" in result["flags"]


def test_erreurs_de_transport(server_url):
    status, body = _post(server_url, "/inconnue", None)
    assert status == 404

    for hostile in (b"pas du json", b"\x80{}"):
        # Le second cas est de l'UTF-8 invalide sans BOM : il échoue en
        # UnicodeDecodeError, pas en JSONDecodeError — le serveur doit
        # répondre 400, jamais fermer la connexion sur une trace.
        req = urllib.request.Request(server_url + "/verify", data=hostile, method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 400, hostile

    status, body = _post(server_url, "/verify", {})
    assert status == 400
    assert "envelope_b64" in body["error"]


def test_enveloppe_charabia_rejetee_proprement(server_url):
    """Un CBOR illisible traverse le pipeline comme rejet motivé, pas comme 500."""
    status, result = _post(server_url, "/verify", {"envelope_b64": _b64(b"pas du cbor")})
    assert status == 200
    assert result["level"] == "REJECTED"
    assert "MALFORMED_ENVELOPE" in result["flags"]
