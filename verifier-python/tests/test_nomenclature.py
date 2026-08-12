"""La §4 bis de la spec est-elle encore vraie ?

Le dépôt n'a aucun générateur : la spec et le code se tiennent synchrones à
la main. C'est exactement ainsi que l'exemple de la §4 avait fini par citer
`BARO_ABSENT`, `key-attested-strongbox` et `motion-consistent` — trois
jetons que le vérificateur n'a jamais émis. Un intégrateur codant sur cet
exemple aurait filtré dans le vide.

Ce test remplace la consigne par une contrainte. Il collecte ce que le code
peut réellement produire, le confronte à ce que la spec documente, **et
échoue dans les deux sens** : un jeton non documenté est une dérive, un
jeton documenté mais jamais émis en est une autre, plus insidieuse encore
puisqu'elle décrit un logiciel qui n'existe pas.

Le sens du contrôle est ici sans danger : rien n'est vérifié à partir d'une
entrée hostile, on compare deux artefacts du dépôt.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from probative import errors

SRC = Path(__file__).resolve().parents[1] / "src" / "probative"
SPEC = Path(__file__).resolve().parents[2] / "docs" / "envelope-spec.md"

# Jetons produits par interpolation, donc invisibles à une lecture statique.
# Ils sont décrits en prose sous les tableaux plutôt qu'en ligne, et exclus
# ici pour que le test ne réclame pas de documenter une famille ouverte.
EVIDENCE_DYNAMIQUE = {"null-verifier:"}

# Code de repli de la classe de base : documenté, mais aucune levée ne le
# porte. On l'exclut du sens « documenté donc émis ».
CODES_SANS_LEVEE = {"UNSPECIFIED"}


def _chaines_collectees() -> tuple[set[str], set[str]]:
    """Drapeaux et jetons d'`evidence` littéraux, extraits par AST.

    L'AST plutôt qu'une expression régulière : `evidence.append("x")` et
    `evidence=["x"]` sont deux formes du même fait, et une regex qui
    attraperait les deux attraperait aussi les commentaires.
    """
    flags: set[str] = set()
    evidence: set[str] = set()

    for fichier in sorted(SRC.rglob("*.py")):
        arbre = ast.parse(fichier.read_text(encoding="utf-8"))
        for noeud in ast.walk(arbre):
            if not isinstance(noeud, ast.Call):
                continue

            # `<quelque chose>.flags.append("X")`
            if (
                isinstance(noeud.func, ast.Attribute)
                and noeud.func.attr == "append"
                and noeud.args
            ):
                cible = noeud.func.value
                nom = (
                    cible.attr
                    if isinstance(cible, ast.Attribute)
                    else cible.id
                    if isinstance(cible, ast.Name)
                    else None
                )
                premier = noeud.args[0]
                if isinstance(premier, ast.Constant) and isinstance(premier.value, str):
                    if nom == "flags":
                        flags.add(premier.value)
                    elif nom == "evidence":
                        evidence.add(premier.value)

            # `PropertyResult(..., evidence=["X"])`
            for kw in noeud.keywords:
                if kw.arg not in ("evidence", "flags") or not isinstance(
                    kw.value, ast.List
                ):
                    continue
                for element in kw.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(
                        element.value, str
                    ):
                        cible_set = flags if kw.arg == "flags" else evidence
                        cible_set.add(element.value)

    return flags, evidence


def _premiere_colonne(titre: str) -> set[str]:
    """Jetons entre accents graves, première colonne du tableau sous `titre`."""
    texte = SPEC.read_text(encoding="utf-8")
    debut = texte.index(titre)
    fin = texte.find("\n### ", debut + len(titre))
    if fin == -1:
        fin = texte.find("\n---", debut)
    section = texte[debut:fin]
    return set(re.findall(r"^\|\s*`([^`]+)`\s*\|", section, re.MULTILINE))


def _codes_de_rejet() -> set[str]:
    return {
        classe.code
        for classe in vars(errors).values()
        if isinstance(classe, type) and issubclass(classe, errors.VerificationError)
    }


def test_tous_les_drapeaux_emis_sont_documentes() -> None:
    emis, _ = _chaines_collectees()
    documentes = _premiere_colonne("### 4 bis.2 Drapeaux")

    assert emis - documentes == set(), "drapeaux émis mais absents de la spec §4 bis.2"


def test_aucun_drapeau_documente_n_est_fictif() -> None:
    """Le sens qui manquait à l'exemple de la §4 : documenter l'inexistant."""
    emis, _ = _chaines_collectees()
    documentes = _premiere_colonne("### 4 bis.2 Drapeaux")
    codes = _codes_de_rejet()

    # Un rejet recopie son code dans `flags` : ces codes sont donc des
    # drapeaux légitimes sans jamais passer par `flags.append`.
    assert documentes - emis - codes == set(), "drapeaux documentés que rien n'émet"


def test_tous_les_jetons_evidence_emis_sont_documentes() -> None:
    _, emis = _chaines_collectees()
    documentes = _premiere_colonne("### 4 bis.3 Jetons")

    manquants = {
        jeton
        for jeton in emis - documentes
        if not any(jeton.startswith(p) for p in EVIDENCE_DYNAMIQUE)
    }
    assert manquants == set(), "jetons d'evidence émis mais absents de la spec §4 bis.3"


def test_aucun_jeton_evidence_documente_n_est_fictif() -> None:
    _, emis = _chaines_collectees()
    documentes = _premiere_colonne("### 4 bis.3 Jetons")

    assert documentes - emis == set(), "jetons d'evidence documentés que rien n'émet"


def test_tous_les_codes_de_rejet_sont_documentes() -> None:
    documentes = _premiere_colonne("### 4 bis.1 Codes de rejet")

    assert _codes_de_rejet() - documentes == set(), "codes de rejet non documentés"


def test_aucun_code_de_rejet_documente_n_est_fictif() -> None:
    documentes = _premiere_colonne("### 4 bis.1 Codes de rejet")

    assert documentes - _codes_de_rejet() == set(), "codes de rejet documentés qui n'existent pas"


@pytest.mark.parametrize(
    ("enumeration", "titre"),
    [("level", "STRONG"), ("grade", "A"), ("profile", "core")],
)
def test_les_ensembles_fermes_figurent_dans_la_spec(enumeration: str, titre: str) -> None:
    """Garde-fou léger : la table des ensembles fermés cite bien chaque famille."""
    texte = SPEC.read_text(encoding="utf-8")
    section = texte[texte.index("### Ensembles fermés") : texte.index("### 4 bis.1")]

    assert f"`{enumeration}`" in section
    assert f"`{titre}`" in section


def test_l_exemple_de_la_section_4_n_utilise_que_des_jetons_reels() -> None:
    """C'est cet exemple qui avait dérivé ; il doit rester sous surveillance."""
    _, emis = _chaines_collectees()
    texte = SPEC.read_text(encoding="utf-8")
    exemple = texte[texte.index('"level": "STANDARD"') : texte.index("**`profile` est")]

    cites = set(re.findall(r'"([a-z][a-z0-9:-]*-[a-z0-9:-]+)"', exemple))
    inconnus = {j for j in cites if j not in emis and j != "level_reason"}

    assert inconnus == set(), f"l'exemple de la §4 cite des jetons inexistants : {inconnus}"
