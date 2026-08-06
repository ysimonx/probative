# ADR-0002 — Preuve de fraicheur dans l'en-tete non protege

**Statut :** accepte
**Date :** 2026-08

## Contexte

Le jeton Play Integrity ou l'assertion App Attest ne peut pas etre couvert par la
signature COSE : il est produit *apres* que la charge utile existe, puisqu'il s'engage
sur son condensat.

## Decision

Le jeton est place dans l'en-tete **non protege**, et se lie au contenu par la regle R1 :

    challenge = SHA-256( payload_bytes || nonce )

## Justification

L'absence de signature sur cet en-tete n'est pas une faiblesse. Le jeton n'est valide que
pour ce condensat precis : le modifier ou le deplacer sur une autre charge utile invalide
la verification a l'etape 4 du pipeline.

## Consequences

- **R1 ne doit jamais etre assouplie.** Sans elle, l'enveloppe atteste seulement qu'un
  appareil sain existe quelque part — ce qui ne prouve rien.
- La contrainte de taille du `requestHash` de Play Integrity doit etre validee pendant le
  spike. Si le condensat de 32 octets ne passe pas tel quel, un niveau d'indirection sera
  necessaire et cette ADR devra etre revisee.
