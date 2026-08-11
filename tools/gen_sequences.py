#!/usr/bin/env python3
"""Génère les diagrammes de séquence de `docs/architecture.html`.

Ces deux figures ne sont pas dessinées à la main : leur géométrie est
calculée. Chaque message occupe un bloc [libellé, précision, flèche] et le
curseur vertical avance selon la présence ou non d'une ligne de précision,
ce qui garantit que les groupes restent visuellement distincts quel que
soit le contenu.

Usage :

    python tools/gen_sequences.py

Le script réécrit uniquement ce qui se trouve entre les marqueurs
`<!-- gen:nom -->` et `<!-- /gen:nom -->` du document. Le reste de la page
est écrit à la main et n'est jamais touché.

Aucune dépendance : bibliothèque standard uniquement.
"""

from __future__ import annotations

import pathlib
import re
import sys
from collections.abc import Callable
from typing import Any
from xml.sax.saxutils import escape

RACINE = pathlib.Path(__file__).resolve().parent.parent
CIBLE = RACINE / "docs" / "architecture.html"

# --- géométrie ----------------------------------------------------------
HEAD_Y, HEAD_H = 24, 46
LANE_TOP = HEAD_Y + HEAD_H            # bas des en-têtes de participants
MARGE_HAUTE = 10                      # air sous les en-têtes
GUTTER_X = 38                         # numéros de message, alignés à droite
APRES_FLECHE = 12                     # blanc sous une flèche
DY_AVEC_SUB = 40                      # curseur -> flèche, avec précision
DY_SANS_SUB = 26                      # curseur -> flèche, sans précision
LBL_AVEC_SUB = 25                     # flèche -> libellé, avec précision
LBL_SANS_SUB = 10                     # flèche -> libellé, sans précision
SUB_AU_DESSUS = 10                    # flèche -> précision
BOUCLE_W = 30                         # largeur d'un message réflexif


def msg(frm: int, to: int, label: str, sub: str | None = None,
        accent: bool = False, dashed: bool = False) -> dict[str, Any]:
    """Message d'une ligne de vie vers une autre."""
    return {"kind": "msg", "frm": frm, "to": to, "label": label, "sub": sub,
            "accent": accent, "dashed": dashed}


def selfmsg(lane: int, label: str, sub: str | None = None,
            accent: bool = False) -> dict[str, Any]:
    """Message réflexif : l'acteur agit sans parler à personne."""
    return {"kind": "self", "frm": lane, "to": lane, "label": label, "sub": sub,
            "accent": accent, "dashed": False}


def phase(title: str) -> dict[str, Any]:
    """Séparateur de phase, avec son filet."""
    return {"kind": "phase", "title": title}


def band_open(title: str) -> dict[str, Any]:
    """Ouvre un encadré couvrant les messages suivants."""
    return {"kind": "band_open", "title": title}


def band_close() -> dict[str, Any]:
    return {"kind": "band_close"}


def build(width: int,
          participants: list[tuple[str, str, int, int]],
          items: list[dict[str, Any]],
          aria: str) -> str:
    """Assemble un diagramme. `participants` : (titre, sous-titre, cx, largeur)."""
    lanes = [p[2] for p in participants]
    derniere = len(participants) - 1
    bord_gauche = min(lanes) + 10

    corps: list[str] = []
    bandes: list[tuple[int, int]] = []
    bande_en_cours: int | None = None
    y = LANE_TOP + MARGE_HAUTE
    n = 0

    for it in items:
        if it["kind"] == "phase":
            y += 16
            corps.append(f'<text class="d-phase" x="52" y="{y}">{escape(it["title"])}</text>')
            y += 8
            corps.append(f'<line class="d-grid" x1="52" y1="{y}" x2="{width - 10}" y2="{y}" />')
            y += 16
            continue

        if it["kind"] == "band_open":
            y += 10
            bande_en_cours = y
            y += 12
            corps.append(f'<text class="d-phase" x="64" y="{y}">{escape(it["title"])}</text>')
            y += 8
            continue

        if it["kind"] == "band_close":
            assert bande_en_cours is not None, "band_close sans band_open"
            bandes.append((bande_en_cours, y + 8))
            bande_en_cours = None
            y += 14
            continue

        n += 1
        avec_sub = it["sub"] is not None
        ay = y + (DY_AVEC_SUB if avec_sub else DY_SANS_SUB)
        ly = ay - (LBL_AVEC_SUB if avec_sub else LBL_SANS_SUB)

        trait = "d-acc-line" if it["accent"] else ("d-dash" if it["dashed"] else "d-line")
        pointe = "d-acc-fill" if it["accent"] else "d-fill-line"

        # Le numéro s'aligne sur le libellé, pas sur la flèche : il
        # appartient au groupe qui commence, pas à l'espace qui précède.
        corps.append(f'<text class="d-num" x="{GUTTER_X}" y="{ly}" text-anchor="end">{n:02d}</text>')

        if it["kind"] == "self":
            cx = lanes[it["frm"]]
            corps.append(
                f'<path class="{trait}" d="M {cx} {ay - 5} L {cx + BOUCLE_W} {ay - 5} '
                f'L {cx + BOUCLE_W} {ay + 5} L {cx + 9} {ay + 5}" />'
            )
            corps.append(
                f'<polygon class="{pointe}" points="{cx},{ay + 5} '
                f'{cx + 9},{ay + 0.5} {cx + 9},{ay + 9.5}" />'
            )
            # Sur la dernière voie, le libellé n'a de place qu'à gauche.
            tx, ancre = (cx - 12, ' text-anchor="end"') if it["frm"] == derniere else (bord_gauche, "")
        else:
            x1, x2 = lanes[it["frm"]], lanes[it["to"]]
            pointe_dx = 9 if x2 > x1 else -9
            corps.append(f'<line class="{trait}" x1="{x1}" y1="{ay}" x2="{x2 - pointe_dx}" y2="{ay}" />')
            corps.append(
                f'<polygon class="{pointe}" points="{x2},{ay} '
                f'{x2 - pointe_dx},{ay - 4.5} {x2 - pointe_dx},{ay + 4.5}" />'
            )
            tx, ancre = bord_gauche, ""

        corps.append(f'<text class="d-t" x="{tx}" y="{ly}"{ancre}>{escape(it["label"])}</text>')
        if avec_sub:
            corps.append(
                f'<text class="d-sub" x="{tx}" y="{ay - SUB_AU_DESSUS}"{ancre}>'
                f'{escape(it["sub"])}</text>'
            )

        y = ay + APRES_FLECHE

    bas_lignes = y + 10
    hauteur = bas_lignes + 24

    out = [f'<svg viewBox="0 0 {width} {hauteur}" role="img" aria-label="{escape(aria)}">']

    # Ordre de tracé : encadrés au fond, puis lignes de vie, puis en-têtes,
    # puis les messages par-dessus.
    for haut, bas in bandes:
        out.append(
            f'<rect class="d-band" x="52" y="{haut}" width="{width - 62}" '
            f'height="{bas - haut}" rx="5" fill-opacity="0.45" />'
        )
    for _, _, cx, _ in participants:
        out.append(f'<line class="d-life" x1="{cx}" y1="{LANE_TOP}" x2="{cx}" y2="{bas_lignes}" />')
    for titre, sous_titre, cx, bw in participants:
        out.append(
            f'<rect class="d-head" x="{cx - bw // 2}" y="{HEAD_Y}" '
            f'width="{bw}" height="{HEAD_H}" rx="5" />'
        )
        out.append(
            f'<text class="d-head-t" x="{cx}" y="{HEAD_Y + 22}" '
            f'text-anchor="middle">{escape(titre)}</text>'
        )
        out.append(
            f'<text class="d-head-s" x="{cx}" y="{HEAD_Y + 37}" '
            f'text-anchor="middle">{escape(sous_titre)}</text>'
        )
    out += corps
    out.append("</svg>")
    return "\n          ".join(out)


# --- diagramme : enrôlement ---------------------------------------------

ENROLEMENT = build(
    1040,
    [("Application", "code considéré hostile", 150, 190),
     ("Puce sécurisée", "Keystore · Secure Enclave", 455, 190),
     ("Attestation", "Google · Apple", 690, 180),
     ("Serveur", "seul juge", 905, 170)],
    [
        msg(0, 3, "Demande l'enrôlement", "à la première ouverture de l'application"),
        msg(3, 0, "Défi d'enrôlement", "aléa serveur, à usage unique"),
        msg(0, 1, "Génère une paire de clés, défi lié", "setAttestationChallenge · generateKey"),
        msg(1, 0, "Clé publique + preuve d'origine", "la clé privée ne sort jamais de la puce"),
        band_open("iOS uniquement — sur Android la preuve est déjà la chaîne X.509 de l'étape 04"),
        msg(0, 2, "Atteste cette clé", "clientDataHash = défi d'enrôlement", accent=True),
        msg(2, 0, "Objet d'attestation", "vérifiable jusqu'à la racine Apple", accent=True),
        band_close(),
        msg(0, 3, "Clé publique, preuve, empreinte du binaire"),
        selfmsg(3, "Valide jusqu'à la racine", "racine Google ou Apple"),
        selfmsg(3, "Enregistre l'appareil", "kid, clé publique, niveau"),
        msg(3, 0, "Enrôlé", "aucune capture n'est possible avant ce point"),
    ],
    "Séquence d'enrôlement : le serveur émet un défi, la puce sécurisée génère une paire de "
    "clés liée à ce défi, la preuve d'origine est validée jusqu'à la racine du constructeur, "
    "puis le serveur enregistre la clé publique.",
)

# --- diagramme : capture ------------------------------------------------

CAPTURE = build(
    1080,
    [("Application", "code considéré hostile", 145, 180),
     ("Capteurs", "caméra · GNSS · inertiels", 405, 170),
     ("Puce sécurisée", "clé non exportable", 620, 160),
     ("Attestation", "Google · Apple", 810, 170),
     ("Serveur", "seul juge", 995, 160)],
    [
        phase("Ouverture · le serveur ouvre l'échange"),
        msg(0, 4, "Demande un nonce"),
        msg(4, 0, "Nonce + profil attendu", "usage unique, validité explicite — règle R3"),
        phase("Collecte · tout est mesuré, rien n'est jugé"),
        msg(0, 1, "Déclenche la capture"),
        msg(1, 0, "Octets bruts du capteur"),
        selfmsg(0, "SHA-256 des octets bruts, en natif",
                "avant tout passage par le code applicatif", accent=True),
        msg(0, 1, "Relève la position"),
        msg(1, 0, "lat, lon, précision, altitude", "source, âge du point, satellites"),
        msg(0, 1, "Relève la corroboration"),
        msg(1, 0, "pression, altitude barométrique", "fenêtre inertielle 10 s, pas, activité"),
        selfmsg(0, "Horloges et posture de l'appareil"),
        phase("Liaison · la règle R1"),
        selfmsg(0, "Sérialise la charge utile en CBOR", "la latence de capture est figée ici"),
        selfmsg(0, "Calcule le défi R1", "SHA-256( charge utile ‖ nonce )", accent=True),
        msg(0, 3, "requestHash / clientDataHash = défi", accent=True),
        msg(3, 0, "Jeton d'intégrité ou assertion", "+ compteur d'assertion sur iOS", accent=True),
        phase("Signature"),
        msg(0, 2, "Signe la structure Signature1", "en-tête protégé : kid, version, profil"),
        msg(2, 0, "Signature ES256, 64 octets", "la clé privée n'a pas quitté la puce"),
        phase("Remise"),
        msg(0, 4, "Enveloppe COSE_Sign1"),
        msg(0, 4, "Octets du contenu", "transfert séparé de l'enveloppe", dashed=True),
        selfmsg(4, "Vérifie en dix étapes"),
        msg(4, 0, "Verdict par propriété", "avec son motif, obligatoire"),
    ],
    "Séquence de capture : le serveur émet un nonce et le profil attendu, l'application "
    "empreinte les octets bruts puis relève position, corroboration, horloges et posture, fige "
    "la charge utile, calcule le défi R1, obtient un jeton d'attestation, signe dans la puce, et "
    "remet l'enveloppe puis les octets du contenu au serveur.",
)

FIGURES = {"sequence-enrolement": ENROLEMENT, "sequence-capture": CAPTURE}


def remplacer(html: str, nom: str, svg: str) -> str:
    """Réécrit le contenu entre `<!-- gen:nom -->` et `<!-- /gen:nom -->`."""
    motif = re.compile(
        rf"(<!-- gen:{re.escape(nom)} -->\n\s*).*?(\n\s*<!-- /gen:{re.escape(nom)} -->)",
        re.S,
    )
    html, remplacements = motif.subn(lambda m: m.group(1) + svg + m.group(2), html)
    if remplacements != 1:
        raise SystemExit(
            f"marqueur 'gen:{nom}' introuvable ou dupliqué dans {CIBLE} "
            f"({remplacements} correspondance(s))"
        )
    return html


def main() -> int:
    html = CIBLE.read_text(encoding="utf-8")
    avant = html
    for nom, svg in FIGURES.items():
        html = remplacer(html, nom, svg)

    if html == avant:
        print(f"{CIBLE.relative_to(RACINE)} : déjà à jour")
        return 0

    CIBLE.write_text(html, encoding="utf-8")
    for nom, svg in FIGURES.items():
        vb = re.search(r'viewBox="([^"]+)"', svg)
        print(f"  {nom:22} viewBox {vb.group(1) if vb else '?'}")
    print(f"{CIBLE.relative_to(RACINE)} : mis à jour")
    return 0


if __name__ == "__main__":
    sys.exit(main())
