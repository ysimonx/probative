# attested-capture

Preuve de présence photographique : une bibliothèque mobile et un vérificateur serveur
permettant d'établir qu'une image donnée a été prise **par ce capteur, à cet endroit, à
cet instant**, sur un appareil non compromis.

> **Nom provisoire.** `attested-capture` est un nom de travail. À vérifier sur pub.dev,
> npm et PyPI simultanément avant publication. Voir `docs/envelope-spec.md` §9.

---

## Le problème

Une photo géolocalisée ordinaire ne prouve rien. Les métadonnées EXIF s'éditent, le GPS se
simule avec une application du magasin, et une incrustation de coordonnées sur l'image est
purement décorative. Dès qu'une décision — un paiement, une validation, un contrôle —
dépend de la photo, l'absence de preuve devient un problème.

## L'approche

Quatre propriétés sont attestées conjointement. Une garantie partielle n'a aucune valeur.

| | Propriété | Moyen |
|---|---|---|
| P1 | Origine | Capture native, empreinte des octets bruts, attestation du binaire |
| P2 | Position | Sources croisées, corroboration barométrique et inertielle |
| P3 | Instant | Défi serveur, horloge monotone, ordonnancement inviolable |
| P4 | Intégrité | Signature par clé matérielle non exportable |

Principe directeur : **le client collecte et signe des preuves, le serveur juge.** Le code
client est intégralement considéré comme hostile. Aucune décision de validité n'est prise
sur l'appareil, et l'API publique n'expose jamais de booléen de confiance.

## État

| Composant | État |
|---|---|
| Modèle de menace | Rédigé — `docs/threat-model.md` |
| Spécification d'enveloppe `ac/0.1` | Proposée — `docs/envelope-spec.md` |
| Vérificateur Python | Fonctionnel, 51 tests au vert |
| Validation Play Integrity | Interface posée, implémentation à faire |
| Validation App Attest | Interface posée, implémentation à faire |
| Cœurs natifs Android / iOS | Encodeurs CBOR/COSE validés contre les vecteurs d'or |
| Plugin Flutter (liaison mince) | Non commencé |
| Module React Native (liaison mince) | Non commencé |
| Banc de triche | Non commencé |

## Structure

```
docs/           Modèle de menace, spécification d'enveloppe, décisions d'architecture
spec/           Schéma CDDL normatif
tools/          Génération des figures de la documentation
verifier-python/  Vérificateur serveur
mobile/android/   Cœur natif Kotlin, publié en AAR
mobile/ios/       Cœur natif Swift, publié en XCFramework
bindings/         Liaisons minces au-dessus des cœurs : Flutter fédéré, React Native
```

Pour une vue d'ensemble du mécanisme — frontière de confiance, anatomie de l'enveloppe,
règle R1, séquences d'enrôlement et de capture, ordre de vérification, attribution des
grades — ouvrir `docs/architecture.html` dans un navigateur. Page autonome, sans dépendance
externe, avec une FAQ en fin de document.

Les deux diagrammes de séquence de cette page sont **générés**, pas dessinés à la main :

```bash
python tools/gen_sequences.py
```

Le script ne réécrit que ce qui se trouve entre les marqueurs `<!-- gen:… -->` du document ;
le reste de la page est rédigé à la main et n'est jamais touché.

## Démarrage

```bash
cd verifier-python
pip install -e ".[dev]"
pytest
```

Le vérificateur se teste intégralement **sans matériel** : `tests/factory.py` simule un
appareil et produit des enveloppes cryptographiquement valides. Ce module fait office
d'implémentation de référence — si un client natif produit une enveloppe que la fabrique
ne saurait pas produire, c'est le client qui s'écarte de la spécification.

## Usage

```python
from attested_capture import Verifier

verifier = Verifier(
    nonce_store=...,
    device_store=...,
    attestation=PlayIntegrityVerifier(...),
)

result = verifier.verify(envelope_bytes, media_bytes=image)

if result.level in (Level.STRONG, Level.STANDARD):
    accepter(image)
else:
    journaliser(result.level_reason, result.flags)
```

Le résultat est structuré par propriété : l'appelant sait *laquelle* des quatre garanties
est faible, pas seulement qu'un score global est bas.

## Limites assumées

Elles sont documentées, pas minimisées. Voir `docs/threat-model.md` §7.

- La **photographie d'un écran** n'est pas détectée en v0.1. C'est le principal angle mort :
  la position est authentique, l'attestation est valide, seul le contenu est faux.
- Un **simulateur GNSS matériel** produit un signal indiscernable côté client.
- Les appareils Android **sans services Google Play** ne peuvent pas être attestés.
- Sur Android, le verdict d'authenticité du binaire signifie « correspond à ce que Google Play
  distribue » : une **diffusion hors Play** conserve le verdict sur l'appareil mais perd celui
  sur l'application. iOS n'a pas cette contrainte, App Attest prouvant l'App ID quel que soit
  le canal.
- La bibliothèque prouve l'**appareil**, jamais l'identité de la personne.

## Feuille de route

- **v0.1** — Attestation, enveloppe signée, position, corroboration inertielle, Android + iOS
- **v0.2** — Signaux radio environnants (Android), réclamations optionnelles
- **v0.3** — Détection de photographie d'écran, alignement C2PA

## Licence

Apache-2.0. La clause de concession de brevet est délibérée : elle compte sur une brique
de sécurité destinée à être intégrée par des tiers.
