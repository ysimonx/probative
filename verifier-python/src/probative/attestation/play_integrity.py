"""Play Integrity — validation du jeton de fraîcheur Android (phase B).

Le jeton est **chiffré par Google** et ne se lit que par un appel à
`decodeIntegrityToken`. Le déchiffrement local exigerait que l'application
soit disponible sur Google Play, ce que la diffusion hors magasin — que ce
dépôt sert délibérément — ne permet pas. Cet appel réseau est donc subi,
non choisi ; ADR-0006 en tire les conséquences.

Contrairement à App Attest, le verdict est **gradué** : l'appareil et
l'application sont jugés séparément, et `AttestationOutcome` a été dessiné
pour recevoir cette granularité.

Ce module n'établit **aucun seuil**. Il traduit ce que Google répond en
faits normalisés ; c'est `GradingPolicy` qui décide ce que ces faits valent.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

from ..errors import AttestationRejected
from .base import AttestationOutcome, AttestationVerifier, DeviceIntegrity
from .google_credentials import AccessTokenProvider

ENDPOINT = "https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken"

# Échelle de Google, du plus fort au plus faible. `MEETS_BASIC_INTEGRITY`
# n'y figure pas par oubli : il n'atteste **pas** un système d'exploitation
# non modifié, seulement un appareil plausible. Le retenir comme signal
# d'intégrité reviendrait à accepter un appareil vraisemblablement rooté —
# voir `_device_integrity` pour le raisonnement complet.
_VERDICT_STRONG = "MEETS_STRONG_INTEGRITY"
_VERDICT_DEVICE = "MEETS_DEVICE_INTEGRITY"

# Émulateur pourvu des services Google Play. Ce n'est pas un degré de
# l'échelle ci-dessus mais une **nature d'environnement** : Google l'émet à
# la place du verdict d'appareil physique, jamais en plus. Le verdict ne
# change donc pas — un émulateur n'a ni objectif ni capteur, il échoue de
# toute façon. Seul le motif change, et l'écart n'est pas cosmétique :
# « appareil compromis » et « environnement virtuel » envoient le support
# sur deux pistes opposées, et c'est une intégration en CI qui paie la
# confusion.
_VERDICT_VIRTUAL = "MEETS_VIRTUAL_INTEGRITY"


class PlayIntegrityVerifier(AttestationVerifier):
    """Valide le jeton accompagnant chaque enveloppe Android.

    `credentials` est la couture d'ADR-0006 : le dépôt n'impose aucune
    bibliothèque d'authentification Google, et un déploiement Cloud injecte
    la sienne.
    """

    def __init__(
        self,
        *,
        package_name: str,
        credentials: AccessTokenProvider,
        endpoint: str = ENDPOINT,
        timeout_s: int = 30,
    ) -> None:
        self._package_name = package_name
        self._credentials = credentials
        self._endpoint = endpoint
        self._timeout_s = timeout_s

    def verify(
        self,
        *,
        platform: str,
        token: bytes,
        expected_challenge: bytes,
        key_id: bytes,
        attestation_key: bytes | None = None,
    ) -> AttestationOutcome:
        # Câblage, pas verdict : ce vérificateur n'a rien à dire d'une
        # enveloppe iOS. On lève, parce que rendre un échec laisserait
        # croire que l'appareil a été jugé.
        if platform != "android":
            raise AttestationRejected(
                f"Play Integrity ne s'applique pas à la plateforme {platform!r}"
            )

        try:
            jeton = token.decode("ascii")
        except UnicodeDecodeError as exc:
            # Illisible, donc structurel : la règle de la spec §5 impose de
            # lever plutôt que de rendre un verdict.
            raise AttestationRejected("jeton Play Integrity non ASCII") from exc

        charge = self._decode_remote(jeton)
        if charge is None:
            # Google injoignable n'est **pas** un échec de l'appareil. Le
            # confondre reviendrait à déclarer compromis tout un parc le
            # jour d'une panne Google.
            return AttestationOutcome(
                integrity=DeviceIntegrity.UNAVAILABLE,
                app_recognized=False,
                hardware_backed=False,
                notes=["Play Integrity injoignable : aucun verdict rendu"],
            )

        details = _mapping(charge, "requestDetails")
        app = _mapping(charge, "appIntegrity")
        device = _mapping(charge, "deviceIntegrity")

        # --- Règle R1, recalculée et non lue -----------------------------
        #
        # L'encodage doit être exactement celui du client (`encodeRequestHash`
        # côté Kotlin) : base64url **sans bourrage**. Une divergence ici
        # casserait R1 en silence, ce qui est le pire mode de défaillance
        # possible — d'où le recalcul plutôt qu'une comparaison d'octets
        # déjà encodés par quelqu'un d'autre.
        attendu = base64.urlsafe_b64encode(expected_challenge).rstrip(b"=").decode()
        recu = _texte(details, "requestHash")
        if recu != attendu:
            return _verdict_defavorable(
                "règle R1 non établie : le requestHash du jeton ne couvre pas cette "
                "charge utile"
            )

        paquet = _texte(details, "requestPackageName")
        if paquet != self._package_name:
            return _verdict_defavorable(
                f"jeton émis pour l'application {paquet!r}, attendue "
                f"{self._package_name!r}"
            )

        integrity, note_integrite = _device_integrity(device)
        reconnu = _texte(app, "appRecognitionVerdict") == "PLAY_RECOGNIZED"

        notes = [note_integrite] if note_integrite else []
        empreinte, note_empreinte = _certificate_digest(app)
        if note_empreinte:
            notes.append(note_empreinte)

        return AttestationOutcome(
            integrity=integrity,
            app_recognized=reconnu,
            # Play Integrity ne dit **rien** de l'adossement matériel de la
            # clé de signature : cela relève de la chaîne d'attestation de
            # clé, validée à l'enrôlement et retenue dans
            # `DeviceRecord.hardware_backed`, que la notation utilise. Ce
            # champ reste donc faux ici, faute d'information, et non par
            # verdict.
            hardware_backed=False,
            app_certificate_digest=empreinte,
            provider_timestamp_ms=_entier(details, "timestampMillis"),
            evidence=["play-integrity:token-valid", "play-integrity:r1-bound"],
            notes=notes,
        )

    # -- Appel réseau ----------------------------------------------------

    def _decode_remote(self, jeton: str) -> Mapping[str, Any] | None:
        """Rend la charge utile déchiffrée, ou `None` si Google est injoignable.

        Lève `AttestationRejected` sur une réponse structurellement fautive :
        un jeton illisible ou une configuration erronée ne sont pas des
        verdicts sur l'appareil.
        """
        url = self._endpoint.format(package=urllib.parse.quote(self._package_name))
        requete = urllib.request.Request(
            url,
            data=json.dumps({"integrity_token": jeton}).encode(),
            headers={
                "Authorization": f"Bearer {self._credentials.access_token()}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(requete, timeout=self._timeout_s) as reponse:
                corps = json.loads(reponse.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            if exc.code >= 500:
                # Panne de leur côté : indisponibilité, pas verdict.
                return None
            raise AttestationRejected(
                f"Play Integrity a refusé le jeton ({exc.code}) : {detail}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        except ValueError as exc:
            raise AttestationRejected("réponse Play Integrity illisible") from exc

        if not isinstance(corps, Mapping):
            raise AttestationRejected("réponse Play Integrity : objet attendu")
        charge = corps.get("tokenPayloadExternal")
        if not isinstance(charge, Mapping):
            raise AttestationRejected("réponse Play Integrity sans tokenPayloadExternal")
        return charge


# -- Traduction des verdicts ---------------------------------------------


def _device_integrity(device: Mapping[str, Any]) -> tuple[DeviceIntegrity, str]:
    """Traduit `deviceRecognitionVerdict` — un **tableau**, et c'est le piège.

    Un appareil qui échoue à tous les contrôles se signale par un tableau
    **vide**, jamais par un champ absent ni par une valeur négative. Traiter
    « vide » comme « inconnu » ferait passer un appareil rooté pour un cas
    indéterminé : c'est un `FAILED` explicite.

    `MEETS_BASIC_INTEGRITY` seul est traité comme un échec, et c'est un choix
    conservateur assumé : ce verdict n'atteste pas un système non modifié,
    seulement un appareil plausible. Le retenir comme signal d'intégrité
    contredirait ce que le modèle de menace cherche à établir.

    `MEETS_VIRTUAL_INTEGRITY` est examiné **avant** les verdicts physiques.
    Google ne les mêle pas aujourd'hui, mais l'ordre inverse ferait dépendre
    la lecture d'une exclusivité qu'aucun contrat n'écrit : une réponse
    portant les deux serait notée sur le verdict physique, donc au bénéfice
    de l'émulateur. Resserrer sur une hypothèse qui pourrait tomber coûte
    ici un test ; desserrer coûterait une capture acceptée sans capteur.

    **Réserve, mesurée le 2026-08-12 :** aucun jeton réel n'a jamais porté
    `MEETS_VIRTUAL_INTEGRITY`. Un émulateur Play Store (API 33) délivre bien
    un jeton, mais sa réponse ne contient **aucun** verdict d'appareil — voir
    ci-dessous. Cette branche reste donc écrite d'après la documentation, et
    testée seulement contre une réponse synthétique.
    """
    verdicts = device.get("deviceRecognitionVerdict")
    if verdicts is None:
        # Champ absent d'une réponse **déjà déchiffrée** : Google a parlé, et
        # n'a rien attesté. Ce n'est pas une indisponibilité — celle-là est
        # traitée en amont, quand l'appel lui-même échoue.
        #
        # La distinction n'est pas byzantine : rendre UNAVAILABLE ici lèverait
        # le drapeau ATTESTATION_UNAVAILABLE et enverrait le support chercher
        # une panne Google inexistante, quand la cause est l'appareil.
        #
        # Cas observé le 2026-08-12 sur émulateur Play Store : la réponse
        # porte `"deviceIntegrity": {}` et `appRecognitionVerdict:
        # UNEVALUATED`. Google délivre le jeton et refuse de se porter garant.
        return (
            DeviceIntegrity.FAILED,
            "réponse sans verdict d'appareil : Google n'atteste pas cet appareil",
        )
    if not isinstance(verdicts, Sequence) or isinstance(verdicts, str | bytes):
        raise AttestationRejected("deviceRecognitionVerdict : tableau attendu")

    valeurs = {v for v in verdicts if isinstance(v, str)}
    if _VERDICT_VIRTUAL in valeurs:
        return (
            DeviceIntegrity.FAILED,
            (
                "environnement virtuel : émulateur pourvu des services Google "
                "Play, sans capteur physique"
            ),
        )
    if _VERDICT_STRONG in valeurs:
        return DeviceIntegrity.STRONG, ""
    if _VERDICT_DEVICE in valeurs:
        return DeviceIntegrity.BASIC, ""
    if not valeurs:
        return DeviceIntegrity.FAILED, "aucun verdict d'intégrité : appareil compromis"
    return (
        DeviceIntegrity.FAILED,
        f"intégrité insuffisante : {', '.join(sorted(valeurs))}",
    )


def _certificate_digest(app: Mapping[str, Any]) -> tuple[str | None, str]:
    """Empreinte du certificat de signature, telle que **Google** la calcule.

    Non falsifiable par le client, donc utilisable pour distinguer une build
    du déploiement d'un binaire reconditionné — forcément resigné.
    """
    empreintes = app.get("certificateSha256Digest")
    if empreintes is None:
        return None, ""
    if not isinstance(empreintes, Sequence) or isinstance(empreintes, str | bytes):
        raise AttestationRejected("certificateSha256Digest : tableau attendu")

    valeurs = [e for e in empreintes if isinstance(e, str)]
    if not valeurs:
        return None, ""
    if len(valeurs) > 1:
        # Signature multiple : on retient la première, et on le dit. Taire
        # cette réduction ferait échouer une comparaison à la liste
        # d'empreintes autorisées sans motif visible.
        return valeurs[0], (
            f"{len(valeurs)} certificats de signature, seule la première "
            "empreinte est retenue"
        )
    return valeurs[0], ""


def _verdict_defavorable(motif: str) -> AttestationOutcome:
    """Échec rendu **comme un verdict**, non comme une levée.

    Même règle que côté App Attest, imposée par la spec §5 : ce qui est
    illisible lève, ce qui est un verdict sur l'appareil ou l'application
    retourne. `UNTRUSTED` et `REJECTED` ne disent pas la même chose à
    l'appelant.
    """
    return AttestationOutcome(
        integrity=DeviceIntegrity.FAILED,
        app_recognized=False,
        hardware_backed=False,
        notes=[f"play-integrity : {motif}"],
    )


# -- Décodage défensif ---------------------------------------------------


def _mapping(charge: Mapping[str, Any], cle: str) -> Mapping[str, Any]:
    valeur = charge.get(cle)
    if valeur is None:
        return {}
    if not isinstance(valeur, Mapping):
        raise AttestationRejected(f"{cle} : objet attendu")
    return valeur


def _texte(bloc: Mapping[str, Any], cle: str) -> str | None:
    valeur = bloc.get(cle)
    if valeur is None:
        return None
    if not isinstance(valeur, str):
        raise AttestationRejected(f"{cle} : chaîne attendue")
    return valeur


def _entier(bloc: Mapping[str, Any], cle: str) -> int | None:
    """`timestampMillis` voyage en **chaîne** dans le JSON de Google."""
    valeur = bloc.get(cle)
    if valeur is None:
        return None
    try:
        return int(valeur)
    except (TypeError, ValueError) as exc:
        raise AttestationRejected(f"{cle} : entier attendu") from exc
