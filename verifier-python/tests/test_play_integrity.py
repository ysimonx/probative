"""Phase B — Play Integrity, éprouvé hors ligne.

Les réponses sont synthétiques, mais **calquées sur une réponse réelle** :
celle qu'a rendue `decodeIntegrityToken` le 2026-08-12 pour un jeton capturé
sur SM-X200. Les noms de champs, leurs types — `timestampMillis` est une
chaîne, `deviceRecognitionVerdict` un tableau — et jusqu'aux valeurs
observées viennent de là. Un test bâti sur une réponse imaginée ne prouverait
que la cohérence du test avec lui-même.

Les jetons réels ne sont **jamais versionnés** : le plan du spike l'interdit,
et un jeton est de toute façon lié à un défi R1 précis.

Le sens du contrôle suit la spec §5 : ce qui est illisible lève, ce qui est
un verdict sur l'appareil ou l'application retourne un résultat en échec.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any, Self

import pytest

from probative.attestation.base import DeviceIntegrity
from probative.attestation.play_integrity import PlayIntegrityVerifier
from probative.errors import AttestationRejected

PACKAGE = "org.probative.demo"
CERT = "YxTPkqqTg9uWc30LWhHznOA_xp59hA2jJliTXMEIHZ8"
DEFI = hashlib.sha256(b"charge utile et nonce").digest()


def _request_hash(defi: bytes = DEFI) -> str:
    """Même encodage que `PlayIntegrity.encodeRequestHash` côté Kotlin."""
    return base64.urlsafe_b64encode(defi).rstrip(b"=").decode()


def _reponse(
    *,
    request_hash: str | None = None,
    package: str = PACKAGE,
    app_verdict: str = "PLAY_RECOGNIZED",
    # `None` signifie « champ absent de la réponse », distinct d'un tableau
    # vide — cette nuance est précisément ce que plusieurs tests exercent.
    device_verdicts: Sequence[str] | None = ("MEETS_DEVICE_INTEGRITY",),
    certificats: Sequence[str] | None = None,
    timestamp: str | None = "1786527394091",
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "requestPackageName": package,
        "requestHash": request_hash if request_hash is not None else _request_hash(),
    }
    if timestamp is not None:
        details["timestampMillis"] = timestamp

    app: dict[str, Any] = {
        "appRecognitionVerdict": app_verdict,
        "packageName": package,
        "certificateSha256Digest": list(certificats) if certificats is not None else [CERT],
        "versionCode": "1",
    }
    device: dict[str, Any] = {}
    if device_verdicts is not None:
        device["deviceRecognitionVerdict"] = list(device_verdicts)

    return {
        "tokenPayloadExternal": {
            "requestDetails": details,
            "appIntegrity": app,
            "deviceIntegrity": device,
            "accountDetails": {"appLicensingVerdict": "UNEVALUATED"},
        }
    }


class _Corps:
    def __init__(self, contenu: bytes) -> None:
        self._contenu = contenu

    def read(self) -> bytes:
        return self._contenu

    def close(self) -> None:
        """`HTTPError` referme le corps qu'on lui passe."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Identifiants:
    """Couture d'ADR-0006, bouchonnée : aucun appel au serveur de jetons."""

    def access_token(self) -> str:
        return "jeton-d-acces-de-test"


def _verifier(**kw: Any) -> PlayIntegrityVerifier:
    return PlayIntegrityVerifier(
        package_name=PACKAGE, credentials=_Identifiants(), **kw
    )


@pytest.fixture
def repond(monkeypatch: pytest.MonkeyPatch):
    """Installe une réponse HTTP, et rend les requêtes émises."""

    def _installer(corps: dict[str, Any] | None = None, *, erreur: Exception | None = None):
        recues: list[urllib.request.Request] = []

        def _urlopen(request: urllib.request.Request, timeout: int = 0) -> _Corps:
            recues.append(request)
            if erreur is not None:
                raise erreur
            return _Corps(json.dumps(corps).encode())

        monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
        return recues

    return _installer


def _verdict(corps: dict[str, Any], repond, **kw: Any):
    repond(corps)
    return _verifier(**kw).verify(
        platform="android", token=b"jeton", expected_challenge=DEFI, key_id=b"kid"
    )


# --- Chemin nominal -----------------------------------------------------


def test_verdict_nominal(repond) -> None:
    out = _verdict(_reponse(), repond)

    assert out.integrity is DeviceIntegrity.BASIC
    assert out.app_recognized is True
    assert out.app_certificate_digest == CERT
    assert out.provider_timestamp_ms == 1_786_527_394_091
    assert "play-integrity:r1-bound" in out.evidence
    assert "play-integrity:token-valid" in out.evidence


def test_integrite_forte(repond) -> None:
    out = _verdict(_reponse(device_verdicts=["MEETS_STRONG_INTEGRITY"]), repond)
    assert out.integrity is DeviceIntegrity.STRONG


def test_binaire_hors_magasin_reste_jugeable(repond) -> None:
    """`UNRECOGNIZED_VERSION` n'est pas un rejet : c'est le cas de la SM-X200."""
    out = _verdict(_reponse(app_verdict="UNRECOGNIZED_VERSION"), repond)

    assert out.app_recognized is False
    assert out.integrity is DeviceIntegrity.BASIC, "l'appareil reste sain"
    assert out.app_certificate_digest == CERT, "l'empreinte reste exploitable"


def test_le_paquet_est_echappe_dans_l_url(repond) -> None:
    recues = repond(_reponse())
    _verifier().verify(
        platform="android", token=b"j", expected_challenge=DEFI, key_id=b"k"
    )
    assert recues[0].full_url.endswith(f"/{PACKAGE}:decodeIntegrityToken")


# --- Surface S4 : client — R1 et identité de l'application --------------


def test_s4_request_hash_d_une_autre_charge_utile(repond) -> None:
    """L'attaque que R1 doit intercepter : jeton authentique, contenu forgé."""
    autre = hashlib.sha256(b"une autre charge utile").digest()
    out = _verdict(_reponse(request_hash=_request_hash(autre)), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert out.app_recognized is False
    assert any("R1" in n for n in out.notes)


def test_s4_request_hash_avec_bourrage_refuse(repond) -> None:
    """Le mode de défaillance le plus dangereux : un encodage qui diverge.

    Un `=` de bourrage suffit à rendre la comparaison fausse. Si le
    vérificateur l'acceptait, R1 ne tiendrait plus qu'en apparence.
    """
    avec_bourrage = base64.urlsafe_b64encode(DEFI).decode()
    out = _verdict(_reponse(request_hash=avec_bourrage), repond)

    assert out.integrity is DeviceIntegrity.FAILED


def test_s4_jeton_d_une_autre_application(repond) -> None:
    out = _verdict(_reponse(package="com.attaquant.app"), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert any("com.attaquant.app" in n for n in out.notes)


def test_s4_plateforme_ios_leve(repond) -> None:
    """Câblage erroné : lever, sinon on laisserait croire à un jugement."""
    repond(_reponse())
    with pytest.raises(AttestationRejected, match="plateforme"):
        _verifier().verify(
            platform="ios", token=b"j", expected_challenge=DEFI, key_id=b"k"
        )


def test_s4_jeton_non_ascii_leve(repond) -> None:
    repond(_reponse())
    with pytest.raises(AttestationRejected, match="ASCII"):
        _verifier().verify(
            platform="android",
            token=b"\xff\xfe",
            expected_challenge=DEFI,
            key_id=b"k",
        )


# --- Surface S4 : client — l'émulateur ----------------------------------


def test_s4_emulateur_avec_services_play_est_refuse(repond) -> None:
    """Critère §9 du modèle de menace : « capture sur émulateur rejetée ».

    L'émulateur pourvu des services Play passe les contrôles d'intégrité
    système de Google et obtient donc un jeton **parfaitement valide** :
    R1 tient, le paquet est le bon, rien ne cloche structurellement. Seul
    `MEETS_VIRTUAL_INTEGRITY` le nomme, et c'est le seul signal de source
    serveur à le faire — `posture.5` (spec §2.3) est déclaré par le client,
    donc falsifiable par qui a intérêt à le falsifier.
    """
    out = _verdict(_reponse(device_verdicts=["MEETS_VIRTUAL_INTEGRITY"]), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert any("virtuel" in n for n in out.notes)
    assert not any("compromis" in n for n in out.notes), (
        "un émulateur n'est pas un appareil rooté ; confondre les deux motifs "
        "envoie le support chercher un rootage inexistant"
    )


@pytest.mark.parametrize("physique", ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"])
def test_s4_emulateur_prime_sur_un_verdict_physique(repond, physique: str) -> None:
    """Les deux étiquettes ensemble : la virtuelle doit l'emporter.

    Google ne les mêle pas aujourd'hui, et rien ne l'y engage par écrit. Ce
    test fige le fait qu'on ne s'appuie pas sur cette exclusivité : sans
    lui, une évolution de l'API ferait juger un émulateur sur son verdict
    d'appareil — un desserrement silencieux, le mode de défaillance que ce
    dépôt refuse partout ailleurs.
    """
    out = _verdict(_reponse(device_verdicts=[physique, "MEETS_VIRTUAL_INTEGRITY"]), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert any("virtuel" in n for n in out.notes)


# --- Verdicts d'appareil : le piège du tableau vide ---------------------


def test_tableau_de_verdicts_vide_est_un_echec_explicite(repond) -> None:
    """Un appareil compromis se signale par un tableau **vide**.

    Le traiter comme « inconnu » ferait passer un appareil rooté pour un cas
    indéterminé. C'est le piège d'implémentation de cette API.
    """
    out = _verdict(_reponse(device_verdicts=[]), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert any("compromis" in n for n in out.notes)


def test_meets_basic_integrity_seul_est_un_echec(repond) -> None:
    """`MEETS_BASIC_INTEGRITY` n'atteste pas un système non modifié."""
    out = _verdict(_reponse(device_verdicts=["MEETS_BASIC_INTEGRITY"]), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert any("MEETS_BASIC_INTEGRITY" in n for n in out.notes)


def test_verdict_d_appareil_absent_est_un_echec_pas_une_indisponibilite(repond) -> None:
    """Google a répondu, et n'a rien attesté : c'est l'appareil qui est en cause.

    Rendre `UNAVAILABLE` ici lèverait `ATTESTATION_UNAVAILABLE` et enverrait
    le support chercher une panne Google inexistante. L'indisponibilité
    réelle est traitée en amont, quand l'appel lui-même échoue.
    """
    out = _verdict(_reponse(device_verdicts=None), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert any("n'atteste pas cet appareil" in n for n in out.notes)


# --- Émulateur réel — capture du 2026-08-12 -----------------------------


def _reponse_emulateur() -> dict[str, Any]:
    """Réponse **réellement obtenue** d'un émulateur Play Store, API 33.

    Recopiée telle quelle, y compris ses absences, qui sont l'essentiel :
    `deviceIntegrity` est un objet **vide**, et `appIntegrity` ne porte que
    son verdict — ni `packageName`, ni `certificateSha256Digest`, ni
    `versionCode`, ce que la documentation annonce pour `UNEVALUATED`.
    """
    return {
        "tokenPayloadExternal": {
            "requestDetails": {
                "requestPackageName": PACKAGE,
                "timestampMillis": "1786539622929",
                "requestHash": _request_hash(),
            },
            "appIntegrity": {"appRecognitionVerdict": "UNEVALUATED"},
            "deviceIntegrity": {},
            "accountDetails": {"appLicensingVerdict": "UNEVALUATED"},
        }
    }


def test_s4_emulateur_reel_est_en_echec(repond) -> None:
    """Un émulateur obtient un jeton — mais Google ne se porte pas garant.

    C'est le contre-exemple qui compte : le jeton existe, R1 est vérifiée,
    et pourtant rien n'est attesté. Sans ce test, la branche « champ absent »
    n'aurait jamais été exercée contre autre chose qu'une fixture inventée.
    """
    out = _verdict(_reponse_emulateur(), repond)

    assert out.integrity is DeviceIntegrity.FAILED
    assert out.app_recognized is False
    assert out.app_certificate_digest is None, (
        "appIntegrity n'est pas peuplé quand le verdict vaut UNEVALUATED"
    )
    # R1 tient malgré tout : la liaison au contenu ne dépend pas du verdict.
    assert "play-integrity:r1-bound" in out.evidence


def test_s4_emulateur_ne_porte_pas_le_verdict_virtuel(repond) -> None:
    """Réserve inscrite dans le code : `MEETS_VIRTUAL_INTEGRITY` jamais observé.

    Ce test échouera le jour où Google se mettra à l'émettre sur ce chemin —
    et c'est voulu : il faudra alors relire la branche correspondante, qui
    n'est aujourd'hui écrite que d'après la documentation.
    """
    device = _reponse_emulateur()["tokenPayloadExternal"]["deviceIntegrity"]

    assert "deviceRecognitionVerdict" not in device


# --- Disponibilité : une panne Google n'est pas un appareil compromis ----


@pytest.mark.parametrize(
    "erreur",
    [
        urllib.error.URLError("réseau absent"),
        TimeoutError("trop lent"),
        urllib.error.HTTPError("u", 503, "Service Unavailable", {}, None),
    ],
)
def test_google_injoignable_rend_unavailable(repond, erreur: Exception) -> None:
    """Confondre panne et compromission déclarerait tout un parc fautif."""
    repond(erreur=erreur)
    out = _verifier().verify(
        platform="android", token=b"j", expected_challenge=DEFI, key_id=b"k"
    )

    assert out.integrity is DeviceIntegrity.UNAVAILABLE
    assert out.app_recognized is False


def test_refus_4xx_leve(repond) -> None:
    """400/403 relèvent d'un jeton illisible ou d'une configuration fautive."""
    repond(
        erreur=urllib.error.HTTPError(
            "u", 400, "Bad Request", {}, _Corps(b'{"error":"App is not found."}')
        )
    )
    with pytest.raises(AttestationRejected, match="App is not found"):
        _verifier().verify(
            platform="android", token=b"j", expected_challenge=DEFI, key_id=b"k"
        )


# --- Réponses structurellement fautives : lever, jamais juger -----------


def test_reponse_sans_charge_utile_leve(repond) -> None:
    repond({"autre": {}})
    with pytest.raises(AttestationRejected, match="tokenPayloadExternal"):
        _verifier().verify(
            platform="android", token=b"j", expected_challenge=DEFI, key_id=b"k"
        )


def test_verdicts_mal_types_levent(repond) -> None:
    corps = _reponse()
    corps["tokenPayloadExternal"]["deviceIntegrity"]["deviceRecognitionVerdict"] = "MEETS"
    repond(corps)
    with pytest.raises(AttestationRejected, match="tableau attendu"):
        _verifier().verify(
            platform="android", token=b"j", expected_challenge=DEFI, key_id=b"k"
        )


def test_timestamp_mal_type_leve(repond) -> None:
    out_corps = _reponse(timestamp="pas-un-entier")
    repond(out_corps)
    with pytest.raises(AttestationRejected, match="entier attendu"):
        _verifier().verify(
            platform="android", token=b"j", expected_challenge=DEFI, key_id=b"k"
        )


# --- Empreintes de certificat -------------------------------------------


def test_signature_multiple_est_signalee(repond) -> None:
    """Taire la réduction ferait échouer la comparaison sans motif visible."""
    out = _verdict(_reponse(certificats=[CERT, "une-autre-empreinte"]), repond)

    assert out.app_certificate_digest == CERT
    assert any("2 certificats" in n for n in out.notes)


def test_absence_d_empreinte_toleree(repond) -> None:
    """`UNEVALUATED` ne peuple pas `appIntegrity` : ce n'est pas une faute."""
    out = _verdict(_reponse(certificats=[]), repond)

    assert out.app_certificate_digest is None
