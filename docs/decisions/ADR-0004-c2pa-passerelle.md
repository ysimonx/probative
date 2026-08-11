# ADR-0004 — C2PA en passerelle, jamais en autorite

**Statut :** accepte
**Date :** 2026-08

## Contexte

C2PA / Content Credentials s'est impose comme norme d'interoperabilite de la provenance :
specification 2.3 en janvier 2026, 2.4 en avril 2026, programme de conformite avec niveaux
d'assurance. L'adoption a franchi un cap materiel — le Pixel 10 signe *toutes* les photos
de son appareil photo natif par defaut, au niveau d'assurance 2 ; le Galaxy S25 retient la
logique inverse et ne marque que les images retouchees par IA.

La specification §9 laissait ouverte la question : **enveloppe native puis passerelle, ou
manifeste C2PA des le depart ?**

Deux elements tranchent, et aucun n'etait connu a la redaction de la specification.

**1. C2PA ne tient pas ses promesses de securite.** Un travail academique de 2026 conclut
que les specifications et les implementations C2PA n'atteignent aucun de leurs objectifs
de securite revendiques. Quatre points nous concernent directement :

- rien dans les donnees signees ne reference l'horodatage, qui peut donc etre remplace
  sans detection ;
- les **zones d'exclusion** laissent modifier certaines regions du fichier, dont les
  metadonnees GPS, sans invalider la signature ;
- la verification de revocation des certificats est optionnelle ;
- des validateurs conformes rendent des verdicts contradictoires sur un meme fichier.

**2. Un conflit technique avec notre propre format.** Le champ `media[2]` est l'empreinte
des **octets bruts du capteur** et `media[4]` leur taille. Un manifeste C2PA s'incorpore
dans le fichier (boite JUMBF), ce qui change ses octets et sa taille. Faire porter
`media[2]` sur le fichier final creerait une dependance circulaire — le manifeste contient
lui-meme une empreinte du fichier, calculee avec zones d'exclusion — et rendrait notre
signature dependante de la signature C2PA, donc cassable par toute re-signature en aval.

## Decision

1. **Passerelle, jamais autorite.** L'enveloppe native reste le seul artefact sur lequel
   le verificateur fonde son verdict. Un manifeste C2PA est un **export derive et non
   autoritatif**.
2. **Le verificateur ne lit jamais un manifeste C2PA pour juger.** L'y autoriser
   importerait les faiblesses ci-dessus dans notre chaine de decision.
3. **`media[2]` et `media[4]` designent les octets bruts du capteur, definitivement.** Ils
   ne designeront jamais un fichier porteur d'un manifeste.
4. **Le manifeste est produit cote serveur, apres le verdict** — pas sur l'appareil.

## Justification

- **Le point 4 est le plus consequent et le moins evident.** Generer le manifeste cote
  serveur evite d'embarquer une trousse C2PA dans l'AAR et le XCFramework, ce qui
  preserverait la surface minimale d'ADR-0001 et ADR-0003 ; garde le certificat de
  signature sur le serveur, jamais distribue sur des appareils ; et permet au manifeste
  d'exprimer le **resultat de la verification**, ce qu'un manifeste produit sur l'appareil
  ne pourrait pas faire — l'appareil ne juge pas (invariant 1).
- **Invariant 5.** Notre resultat est structure par propriete avec un `level_reason`. Un
  manifeste C2PA porte une confiance de fait binaire. La passerelle traduit vers le
  binaire pour l'ecosysteme sans que le format interne y perde sa granularite.
- **L'incoherence entre validateurs C2PA decoule de l'absence d'arbitre unique.** Notre
  architecture a un arbitre unique par construction ; le lui retirer au profit d'une
  norme qui n'en a pas serait une regression.

## Consequences

- **Deux artefacts, une seule autorite.** Le fichier livre a un consommateur C2PA n'est
  pas celui que le verificateur juge. Les octets bruts doivent donc rester disponibles
  pour toute re-verification ulterieure ; a defaut, le fichier C2PA n'est plus verifiable
  par nous.
- **Engagement operationnel, hors code, a instruire avant d'annoncer la fonctionnalite :**
  signer un manifeste C2PA exige un certificat inscrit dans la liste de confiance du
  programme de conformite. Sans lui, les visualiseurs afficheront « signature valide,
  emetteur inconnu » — ce qui est pire que rien pour un produit qui vend de la preuve.
  C'est une relation avec une autorite de certification, pas une tache d'implementation.
- Le manifeste pourra porter une assertion referencant l'empreinte de l'enveloppe, de
  sorte que les deux artefacts soient lies sans que la dependance s'inverse.
- La generation du manifeste vit entierement hors du chemin critique de capture : elle
  n'entre ni dans la latence `media[6]`, ni dans le perimetre des coeurs natifs.

## Ce qui ferait revenir sur cette decision

Si le programme de conformite C2PA corrigeait la couverture de l'horodatage et les zones
d'exclusion, et si un niveau d'assurance garantissait la liaison a un defi serveur, alors
l'argument « ne pas s'en remettre a C2PA seul » faiblirait. Reexaminer a chaque version
majeure de la specification.
