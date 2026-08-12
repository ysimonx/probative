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
from cryptography.hazmat.primitives.asymmetric import ec
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


# --- Enrôlement attesté Android — phase B ---------------------------------


def _keystore_vector() -> dict:
    path = Path(__file__).parent / "device-vectors" / "keystore-a3-sm-x200.json"
    return json.loads(path.read_text())


def _android_enroll_body(vector: dict) -> dict:
    return {
        "public_key_x962_b64": vector["key"]["publicKeyX962"],
        "platform": "android",
        "attestation_chain_b64": vector["attestation"]["chain"],
        "challenge_b64": vector["attestation"]["challenge"],
    }


def _android_service() -> DevService:
    # Les certificats de la chaîne courent jusqu'en 2031. On fige l'horloge
    # au jour de la capture : sans cela, ces tests deviendraient une bombe à
    # retardement, exactement comme leur pendant App Attest.
    fige = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    return DevService(now=lambda: fige)


def test_enrolement_android_atteste_jusqu_a_la_racine_google():
    """La chaîne du vecteur SM-X200 est ancrée, et la clé est bien la sienne."""
    vector = _keystore_vector()
    reponse = _android_service().enroll(_android_enroll_body(vector))

    assert reponse["attested"] is True
    assert reponse["kid_b64"] == vector["key"]["kid"]


def test_enrolement_android_retient_le_niveau_de_securite_reel():
    """`hardware_backed` vient de l'attestation, jamais du client."""
    vector = _keystore_vector()
    service = _android_service()
    service.enroll(_android_enroll_body(vector))

    kid = base64.b64decode(vector["key"]["kid"])
    assert service.devices.get(kid).hardware_backed is True


def test_enrolement_android_ignore_le_drapeau_declare():
    """Un client qui ment sur son matériel ne doit pas être cru.

    Le drapeau `hardware_backed` du corps est un mode dégradé, réservé au
    cas où aucune attestation n'accompagne l'enrôlement. Dès qu'une chaîne
    est fournie et validée, c'est elle qui fait foi.
    """
    vector = _keystore_vector()
    body = _android_enroll_body(vector) | {"hardware_backed": False}
    service = _android_service()
    service.enroll(body)

    kid = base64.b64decode(vector["key"]["kid"])
    assert service.devices.get(kid).hardware_backed is True, (
        "l'attestation doit primer sur la déclaration du client"
    )


def test_s4_chaine_attestant_une_autre_cle_refusee():
    """Liaison décisive : la chaîne doit porter sur la clé qu'on enrôle.

    Sans ce contrôle, une chaîne authentique obtenue pour une autre clé
    ferait enrôler n'importe laquelle — y compris celle d'un attaquant.
    """
    vector = _keystore_vector()
    autre = ec.generate_private_key(ec.SECP256R1())
    body = _android_enroll_body(vector) | {
        "public_key_x962_b64": _b64(_public_x962(autre))
    }

    with pytest.raises(BadRequest, match="atteste une autre clé"):
        _android_service().enroll(body)


def test_s4_chaine_avec_un_defi_etranger_refusee():
    vector = _keystore_vector()
    body = _android_enroll_body(vector) | {"challenge_b64": _b64(b"x" * 32)}

    with pytest.raises(BadRequest, match="attestation de clé refusée"):
        _android_service().enroll(body)


def test_chaine_android_refusee_sur_plateforme_ios():
    """Câblage erroné : refuser plutôt que de valider une chaîne hors sujet."""
    vector = _keystore_vector()
    body = _android_enroll_body(vector) | {"platform": "ios"}

    with pytest.raises(BadRequest, match="ne s'applique qu'à la plateforme android"):
        _android_service().enroll(body)


@pytest.mark.parametrize(
    "chaine", [[], "pas une liste", [123], ["%%%"]], ids=["vide", "chaine", "entier", "b64"]
)
def test_chaine_mal_formee_refusee(chaine):
    vector = _keystore_vector()
    body = _android_enroll_body(vector) | {"attestation_chain_b64": chaine}

    with pytest.raises(BadRequest):
        _android_service().enroll(body)


def test_enrolement_android_sans_chaine_reste_degrade():
    """Le mode dégradé subsiste : la clé est acceptée sur parole, et ça se voit."""
    vector = _keystore_vector()
    body = {
        "public_key_x962_b64": vector["key"]["publicKeyX962"],
        "platform": "android",
    }
    reponse = _android_service().enroll(body)

    assert reponse["attested"] is False


# --- Configuration de déploiement — .env et empreintes --------------------


def test_dotenv_charge_sans_ecraser_l_environnement(tmp_path, monkeypatch):
    """L'environnement réel prime : une CI doit pouvoir surcharger le fichier."""
    from probative.devserver import _load_dotenv

    fichier = tmp_path / ".env"
    fichier.write_text(
        "# commentaire ignoré\n"
        "PROBATIVE_DEJA_POSEE=depuis-le-fichier\n"
        "\n"
        'PROBATIVE_NOUVELLE="entre guillemets"\n'
        "ligne sans signe egal\n"
    )
    monkeypatch.setenv("PROBATIVE_DEJA_POSEE", "depuis-l-environnement")

    charges = _load_dotenv(fichier)

    assert charges == ["PROBATIVE_NOUVELLE"]
    assert os.environ["PROBATIVE_DEJA_POSEE"] == "depuis-l-environnement"
    assert os.environ["PROBATIVE_NOUVELLE"] == "entre guillemets"


def test_dotenv_absent_ne_leve_pas(tmp_path):
    """Le fichier est facultatif : son absence est le cas nominal."""
    from probative.devserver import _load_dotenv

    assert _load_dotenv(tmp_path / "inexistant") == []


def test_politique_lue_depuis_l_environnement(monkeypatch):
    from probative.devserver import ENV_TRUSTED_CERTS, _policy_from_env

    monkeypatch.setenv(
        ENV_TRUSTED_CERTS,
        "63:14:CF:92:AA:93:83:DB:96:73:7D:0B:5A:11:F3:9C:"
        "E0:3F:C6:9E:7D:84:0D:A3:26:58:93:5C:C1:08:1D:9F",
    )

    politique = _policy_from_env()

    assert politique.trusted_app_certificates == (
        "YxTPkqqTg9uWc30LWhHznOA_xp59hA2jJliTXMEIHZ8",
    )


def test_politique_vide_par_defaut(monkeypatch):
    """Un déploiement qui ne configure rien garde le comportement d'origine."""
    from probative.devserver import ENV_TRUSTED_CERTS, _policy_from_env

    monkeypatch.delenv(ENV_TRUSTED_CERTS, raising=False)

    assert _policy_from_env().trusted_app_certificates == ()
    assert _policy_from_env().deviations() == []


def test_empreinte_mal_formee_refusee(monkeypatch):
    """Mieux vaut refuser de démarrer qu'une liste silencieusement incomplète.

    Le symptôme serait un binaire légitime traité comme reconditionné — le
    diagnostic le plus coûteux de toute la chaîne.
    """
    from probative.devserver import ENV_TRUSTED_CERTS, _policy_from_env

    monkeypatch.setenv(ENV_TRUSTED_CERTS, "yTU-2irSW0V8yOgcrWGbGk1kukC4LYrK6uLfTNN60pQ")

    with pytest.raises(ValueError, match="hexadécimal"):
        _policy_from_env()


# --- Attestation réelle, ou substitut annoncé -----------------------------


def test_sans_configuration_le_substitut_prend_le_relais(monkeypatch):
    """Le repli est légitime — mais il doit être **dit**, jamais silencieux."""
    from probative.devserver import (
        ENV_ANDROID_PACKAGE,
        ENV_SERVICE_ACCOUNT,
        _attestation_from_env,
    )

    monkeypatch.delenv(ENV_ANDROID_PACKAGE, raising=False)
    monkeypatch.delenv(ENV_SERVICE_ACCOUNT, raising=False)

    verificateur, motif = _attestation_from_env()

    assert verificateur is None
    assert ENV_ANDROID_PACKAGE in motif and ENV_SERVICE_ACCOUNT in motif


def test_configuration_partielle_ne_bascule_pas_a_moitie(monkeypatch):
    """Un seul des deux réglages ne suffit pas, et le motif nomme le manquant."""
    from probative.devserver import (
        ENV_ANDROID_PACKAGE,
        ENV_SERVICE_ACCOUNT,
        _attestation_from_env,
    )

    monkeypatch.setenv(ENV_ANDROID_PACKAGE, "org.probative.demo")
    monkeypatch.delenv(ENV_SERVICE_ACCOUNT, raising=False)

    verificateur, motif = _attestation_from_env()

    assert verificateur is None
    assert ENV_SERVICE_ACCOUNT in motif
    assert ENV_ANDROID_PACKAGE not in motif


def test_chemin_de_cle_introuvable_arrete_le_serveur(monkeypatch, tmp_path):
    """Une faute de configuration n'est pas une absence.

    Retomber sur le substitut ici laisserait croire à une campagne qu'elle
    valide une attestation réelle. Mieux vaut refuser de démarrer.
    """
    from probative.devserver import (
        ENV_ANDROID_PACKAGE,
        ENV_SERVICE_ACCOUNT,
        _attestation_from_env,
    )

    monkeypatch.setenv(ENV_ANDROID_PACKAGE, "org.probative.demo")
    monkeypatch.setenv(ENV_SERVICE_ACCOUNT, str(tmp_path / "absent.json"))

    with pytest.raises(SystemExit, match="introuvable"):
        _attestation_from_env()


def test_cle_illisible_arrete_le_serveur(monkeypatch, tmp_path):
    from probative.devserver import (
        ENV_ANDROID_PACKAGE,
        ENV_SERVICE_ACCOUNT,
        _attestation_from_env,
    )

    faux = tmp_path / "service-account.json"
    faux.write_text("{ pas du json de compte de service")
    monkeypatch.setenv(ENV_ANDROID_PACKAGE, "org.probative.demo")
    monkeypatch.setenv(ENV_SERVICE_ACCOUNT, str(faux))

    with pytest.raises(SystemExit):
        _attestation_from_env()


# --- Câblage App Attest (préalable de C4.1) -----------------------------
#
# Même contrat que côté Android : jamais de repli silencieux, et une faute
# de configuration se distingue d'une absence.


def test_app_attest_absent_refuse_plutot_que_de_faire_semblant(monkeypatch):
    """Sans configuration, l'enrôlement Apple est indisponible et le dit."""
    from probative.devserver import (
        ENV_APPLE_TEAM_ID,
        ENV_IOS_BUNDLE_ID,
        _app_attest_from_env,
    )

    monkeypatch.delenv(ENV_APPLE_TEAM_ID, raising=False)
    monkeypatch.delenv(ENV_IOS_BUNDLE_ID, raising=False)

    application, motif = _app_attest_from_env()

    assert application is None
    assert ENV_APPLE_TEAM_ID in motif and ENV_IOS_BUNDLE_ID in motif


def test_app_attest_partiel_nomme_le_reglage_manquant(monkeypatch):
    from probative.devserver import (
        ENV_APPLE_TEAM_ID,
        ENV_IOS_BUNDLE_ID,
        _app_attest_from_env,
    )

    monkeypatch.setenv(ENV_APPLE_TEAM_ID, "9SGKL7VUD3")
    monkeypatch.delenv(ENV_IOS_BUNDLE_ID, raising=False)

    application, motif = _app_attest_from_env()

    assert application is None
    assert ENV_IOS_BUNDLE_ID in motif
    assert ENV_APPLE_TEAM_ID not in motif


def test_app_attest_environnement_par_defaut_est_le_cas_strict(monkeypatch):
    """Le défaut est `production`, jamais `development`.

    Se tromper vers le développement accepterait un binaire de test dans un
    déploiement réel ; l'inverse fait seulement échouer une campagne, et
    bruyamment. Un défaut doit être le cas strict.
    """
    from probative.devserver import (
        ENV_APPATTEST_ENV,
        ENV_APPLE_TEAM_ID,
        ENV_IOS_BUNDLE_ID,
        _app_attest_from_env,
    )

    monkeypatch.setenv(ENV_APPLE_TEAM_ID, "9SGKL7VUD3")
    monkeypatch.setenv(ENV_IOS_BUNDLE_ID, "org.probative.demo")
    monkeypatch.delenv(ENV_APPATTEST_ENV, raising=False)

    application, _ = _app_attest_from_env()

    assert application == ("9SGKL7VUD3", "org.probative.demo", "production")


def test_app_attest_environnement_inconnu_arrete_le_serveur(monkeypatch):
    """Une valeur inconnue ferait attendre un `aaguid` jamais produit.

    L'échec ressemblerait alors à une attestation invalide, ce qui enverrait
    chercher la panne du mauvais côté.
    """
    from probative.devserver import (
        ENV_APPATTEST_ENV,
        ENV_APPLE_TEAM_ID,
        ENV_IOS_BUNDLE_ID,
        _app_attest_from_env,
    )

    monkeypatch.setenv(ENV_APPLE_TEAM_ID, "9SGKL7VUD3")
    monkeypatch.setenv(ENV_IOS_BUNDLE_ID, "org.probative.demo")
    monkeypatch.setenv(ENV_APPATTEST_ENV, "prod")

    with pytest.raises(SystemExit, match="development"):
        _app_attest_from_env()
