#!/usr/bin/env python3
"""Génère les vecteurs d'or dans `verifier-python/tests/vectors/`.

À lancer depuis la racine du dépôt, avec le venv du vérificateur :

    verifier-python/.venv/bin/python tools/gen_vectors.py

La définition des vecteurs vit dans `verifier-python/tests/vectors.py`,
à côté de la fabrique de référence : ce script n'est qu'un lanceur. Un
test pytest compare les fichiers écrits à une régénération — toute
dérive de la fabrique ou de cbor2 casse ce test, jamais silencieusement
les cœurs natifs.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier-python" / "tests"))
sys.path.insert(0, str(ROOT / "verifier-python" / "src"))


def main() -> None:
    from vectors import VECTORS_DIR, write_vectors

    for name in write_vectors():
        print(f"écrit  {VECTORS_DIR.relative_to(ROOT)}/{name}")


if __name__ == "__main__":
    main()
