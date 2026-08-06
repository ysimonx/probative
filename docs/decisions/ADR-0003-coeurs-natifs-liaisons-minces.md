# ADR-0003 — Coeurs natifs autonomes, liaisons minces multi-frameworks

**Statut :** accepte
**Date :** 2026-08

## Contexte

Le depot visait initialement un plugin Flutter federe comme livrable mobile. Le besoin
s'est elargi : pouvoir livrer aussi un module React Native, sans dupliquer la logique de
capture ni fragiliser les garanties. Le risque a ecarter est d'enfouir la logique dans le
code plateforme du plugin Flutter, ce qui la rendrait captive de ce framework.

## Decision

1. **Coeurs natifs autonomes.** `mobile/android/` est un module Gradle publiable en AAR ;
   `mobile/ios/` un package SwiftPM produisant un XCFramework. Aucune dependance a
   Flutter ou React Native dans ces coeurs.
2. **Tout le chemin critique reste natif** : capture, empreinte des octets bruts, defi
   R1, appel d'attestation, signature par cle materielle, assemblage CBOR. Le pont
   Dart/JS ne recoit que l'enveloppe signee, opaque, plus des metadonnees d'affichage
   non autoritatives.
3. **Liaisons minces interchangeables.** Le plugin Flutter federe et le Turbo Module
   React Native consomment les memes artefacts, avec la meme surface d'API conceptuelle.

Structure cible :

    mobile/android/          coeur natif Kotlin -> AAR
    mobile/ios/              coeur natif Swift  -> XCFramework
    bindings/flutter/        plugin federe (mince)
    bindings/react-native/   Turbo Module (mince)

## Justification

- **Prolongement de l'invariant « proprietes, pas plateformes »** : le format
  d'enveloppe est le contrat ; ajouter une liaison ne touche jamais la specification.
- **Pont hors du chemin critique** : la couche JS/Dart est deja reputee hostile
  (invariant 1), mais surtout la latence capture->signature (`media.6`) ne doit pas
  dependre du pont, et aucun re-encodage ne doit pouvoir casser la canonicite CBOR.
- **Arbitre de conformite inchange** : une enveloppe produite via n'importe quelle
  liaison doit etre acceptee par le verificateur Python, `tests/factory.py` restant
  l'implementation de reference.

## Consequences

- Le spike natif doit produire des **artefacts consommables seuls** (AAR, XCFramework),
  pas du code embarque dans un plugin.
- Les octets de la charge utile ne traversent jamais le pont avant signature.
- La verification de disponibilite du nom doit couvrir **npm** en plus de pub.dev et
  PyPI.
- Chaque liaison se valide par un test de bout en bout : enveloppe produite, puis
  acceptee par le verificateur Python.
