# ADR-0001 — Enveloppe COSE_Sign1 plutot que JWS ou format maison

**Statut :** accepte
**Date :** 2026-08

## Contexte

L'enveloppe doit etre signee par une cle materielle, compacte sur reseau mobile, et
verifiable independamment de l'implementation qui l'a produite.

## Decision

`COSE_Sign1` (RFC 8152) sur charge utile CBOR canonique (RFC 8949 §4.2.1), ES256 exclusif.

## Justification

- **CBOR contre JSON** : encodage binaire natif, pas de base64 sur les condensats et les
  jetons d'attestation. Sur une capture typique, l'ecart depasse 30 %.
- **COSE contre JWS** : COSE est le format attendu par l'ecosysteme d'attestation
  materielle, et evite les pieges historiques de JWS (negociation d'algorithme, `alg: none`).
- **ES256 exclusif** : la surface acceptee doit rester minimale. Un seul algorithme, une
  seule structure, tout le reste rejete.
- **Canonicite obligatoire** : deux implementations doivent produire des octets identiques
  pour une meme charge utile, sinon la signature ne se verifie pas.

## Consequences

- Aucune bibliotheque COSE generaliste n'est utilisee cote serveur : le module `cose.py`
  implemente le strict necessaire, ce qui reduit la surface d'attaque et les dependances.
- La verification est possible en Python, Dart, Kotlin et Swift sans dependance lourde.
- Un changement d'algorithme constituera une version majeure.
