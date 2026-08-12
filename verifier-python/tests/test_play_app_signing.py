"""Le certificat de signature d'application Play, confronté au jeton réel.

Ce test ferme une chaîne que trois documents décrivaient sans jamais la
rejouer : **Play Console → certificat → empreinte du jeton**.

Il existe parce que cette chaîne a coûté une demi-journée le 2026-08-12. La
page « Signature d'application » met en évidence deux empreintes qui ne
servent pas — la classique et la post-quantique — et cache derrière un lien
discret le seul certificat qui signe les APK livrés. Épingler la mauvaise
échoue **en silence** : le binaire passe pour non reconnu, exactement comme
un reconditionnement.

Le certificat est **public** : n'importe qui possédant l'application peut
l'en extraire d'un APK livré. Il n'entre donc pas en contradiction avec la
règle « aucun matériel cryptographique réel versionné », qui vise les
secrets.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography import x509

from probative.grading import app_certificate_digest

CERT = (
    Path(__file__).parent
    / "device-vectors"
    / "play-app-signing-deployment-cert.der"
)

# Valeur réellement rapportée par `decodeIntegrityToken` le 2026-08-12, pour
# `org.probative.demo` version 4, installée depuis une piste de test interne.
# Recopiée du jeton déchiffré, jamais dérivée du certificat — sans quoi le
# test comparerait le fichier à lui-même.
DIGEST_DU_JETON = "yTU-2irSW0V8yOgcrWGbGk1kukC4LYrK6uLfTNN60pQ"

# Les deux empreintes que la console affiche en évidence, et qu'il ne faut
# PAS épingler. Présentes ici pour que le test échoue si quelqu'un les
# confondait un jour.
CLASSIQUE = "93:CC:A8:D4:39:0D:5D:37:12:4B:C8:E2:15:E3:1C:EA:49:88:78:A1:C5:4E:ED:18:C2:60:07:84:A1:3A:D2:B6"
POST_QUANTIQUE = "77:2A:2E:FF:DB:91:AE:3A:B0:BE:EE:4F:5C:69:27:E5:72:E3:68:E4:D3:F4:EB:BE:2A:D4:6F:63:C0:D9:B5:B9"


def test_le_certificat_de_deploiement_donne_l_empreinte_du_jeton() -> None:
    """Le contrôle qui compte, fait par recalcul depuis les octets du certificat."""
    der = CERT.read_bytes()
    empreinte = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=")

    assert empreinte.decode() == DIGEST_DU_JETON


def test_la_conversion_depuis_la_console_donne_la_meme_valeur() -> None:
    """`app_certificate_digest` doit relier la forme console à la forme jeton."""
    der = CERT.read_bytes()
    hexa = ":".join(f"{o:02X}" for o in hashlib.sha256(der).digest())

    assert app_certificate_digest(hexa) == DIGEST_DU_JETON


def test_les_deux_empreintes_mises_en_avant_ne_conviennent_pas() -> None:
    """C'est l'erreur que la console invite à commettre.

    Si l'une d'elles correspondait un jour, ce test le signalerait — et il
    faudrait alors relire la §8.2, pas supprimer le test.
    """
    assert app_certificate_digest(CLASSIQUE) != DIGEST_DU_JETON
    assert app_certificate_digest(POST_QUANTIQUE) != DIGEST_DU_JETON


def test_le_certificat_est_bien_celui_de_play_app_signing() -> None:
    """Sujet générique `CN=Android, O=Google Inc.` — convention de Play App Signing.

    Ce n'est pas le signe d'un certificat partagé entre applications : les
    trois certificats de *cette* application le portent également.
    """
    cert = x509.load_der_x509_certificate(CERT.read_bytes())

    assert "O=Google Inc." in cert.subject.rfc4514_string()
    assert cert.subject == cert.issuer, "certificat de signature auto-signé attendu"
