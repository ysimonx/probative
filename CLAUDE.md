# attested-capture

## Pourquoi ce projet existe

Une photo géolocalisée ordinaire ne prouve rien : l'EXIF s'édite, le GPS se simule avec
une application du magasin, une incrustation de coordonnées est décorative. Dès qu'une
décision dépend de la photo, il faut une preuve opposable.

Ce dépôt produit une bibliothèque mobile et un vérificateur serveur qui établissent
qu'une image a été prise **par ce capteur, à cet endroit, à cet instant**, sur un
appareil non compromis.

Projet personnel indépendant, destiné à être réutilisé sur plusieurs projets et
éventuellement publié. Licence Apache-2.0.

## Invariants — ne jamais transiger

1. **Le client collecte et signe des preuves, le serveur juge.** Aucune décision de
   validité sur l'appareil. L'API publique n'expose jamais de booléen de confiance.
2. **La règle R1 ne s'assouplit pas.** Le défi soumis au service d'attestation vaut
   exactement `SHA-256(payload_bytes || nonce)`. Sans elle, l'enveloppe atteste
   seulement qu'un appareil sain existe quelque part — ce qui ne prouve rien.
3. **Aucun vocabulaire métier dans ce dépôt.** Pas de « chantier », pas de nom de
   client, pas de domaine applicatif. Uniquement `capture`, `subject`, `evidence`.
   Cette règle protège la réutilisabilité et l'antériorité du code ; elle prime sur
   la lisibilité d'un exemple.
4. **Le format raisonne en propriétés, pas en plateformes.** Android et iOS atteignent
   le même niveau par des chemins différents. Aucun champ obligatoire propre à une
   plateforme.
5. **Le résultat de vérification est structuré par propriété**, jamais un score seul.
   `level_reason` est obligatoire : un rejet sans motif exploitable est ingérable en
   support.

## Documents de référence — à lire avant toute modification de fond

| Fichier | Rôle |
|---|---|
| `docs/architecture.html` | Vue d'ensemble illustrée du mécanisme, séquences et FAQ. Point d'entrée pour comprendre ; ne fait pas autorité. Les deux diagrammes de séquence sont générés par `tools/gen_sequences.py` — ne pas les éditer à la main. |
| `docs/threat-model.md` | Spécification de référence. Toute fonctionnalité doit répondre à une menace identifiée. |
| `docs/envelope-spec.md` | Format `ac/0.1`, règles de liaison R1/R2/R3, ordre de vérification |
| `docs/decisions/` | ADR. Les compléter plutôt que revenir silencieusement sur un choix. |
| `spec/envelope-v0.1.cddl` | Extrait de la spec, **ne pas éditer à la main** |

## Structure

```
docs/             Modèle de menace, spec d'enveloppe, ADR, vue d'ensemble
spec/             Schéma CDDL normatif (généré)
tools/            Génération des figures de la documentation
verifier-python/  Vérificateur serveur
mobile/android/   Cœur natif Kotlin (AAR) — non commencé
mobile/ios/       Cœur natif Swift (XCFramework) — non commencé
bindings/         Liaisons minces : plugin Flutter fédéré, module React Native — non commencées
```

## Commandes

```bash
cd verifier-python
source .venv/bin/activate
pip install -e ".[dev]"
pytest              # 50 tests doivent passer
ruff check .
mypy src
```

## Conventions

- Python ≥ 3.11, typage strict, `from __future__ import annotations`.
- Docstrings et commentaires **en français**. Identifiants en anglais.
- Les commentaires expliquent *pourquoi*, pas *quoi*.
- Tout seuil de décision va dans les constantes en tête de `grading.py`, jamais en
  dur dans le code : ils seront recalibrés sur données réelles.
- Chaque test d'attaque référence la surface du modèle de menace (`test_s1_`, `test_s4_`…).
- Entrée hostile : décodage défensif via `Mapping` / `Sequence`, jamais `dict` / `list`
  (cbor2 en mode canonique restitue des types immuables).
- Aucun matériel cryptographique réel versionné. Voir `.gitignore`.

## État actuel

| Composant | État |
|---|---|
| Modèle de menace, spec d'enveloppe, ADR | Rédigés |
| Vérificateur Python, pipeline étapes 1–10 | Fonctionnel, 40 tests au vert |
| `PlayIntegrityVerifier`, `AppAttestVerifier` | Interfaces posées, `NotImplementedError` |
| Cœurs natifs Android / iOS | Non commencés |
| Liaisons Flutter / React Native | Non commencées |
| Banc de triche | Non commencé |

## Prochaine étape

**Spike d'attestation natif** — plan détaillé et phases dans
`docs/spike-attestation.md`. Cible précise : produire une enveloppe qu'un appareil
réel fait accepter par le vérificateur. `verifier-python/tests/factory.py` est
l'implémentation de référence — si le natif produit une enveloppe que la fabrique ne
saurait pas produire, c'est le natif qui s'écarte de la spécification.

Les cœurs du spike doivent être livrés comme artefacts autonomes (AAR, XCFramework),
sans dépendance à un framework : c'est la condition de la stratégie multi-frameworks
Flutter + React Native (ADR-0003). Tout le chemin critique reste natif ; le pont
Dart/JS ne reçoit que l'enveloppe signée, opaque.

Deux inconnues à lever pendant le spike, susceptibles de forcer une révision de la spec :

- la contrainte de taille du `requestHash` de Play Integrity ;
- la latence capture→signature réelle sur appareils d'entrée de gamme, qui conditionne
  l'exploitabilité du champ `media.6` comme discriminant.

## Angle mort assumé

La **photographie d'un écran** n'est pas détectée en v0.1 : position authentique,
attestation valide, contenu faux. C'est pour cela que `origin` est plafonné au grade B.
Ne pas lever ce plafond sans implémenter la détection.
