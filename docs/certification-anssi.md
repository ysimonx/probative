# Piste ANSSI — profil de protection, CSPN et opposabilité

**Note stratégique, rédigée le 2026-08-12.** Comme `etat-de-l-art.md` : datée,
revérifier les faits (référentiels, coûts, procédures) avant de s'en servir pour
un arbitrage.

## Contexte

Ce dépôt a été conçu après l'idée d'élaborer un « profil de protection » auprès de
l'ANSSI. Cette note examine ce que cette origine a laissé dans la structure du
projet, et ce que serait une trajectoire réaliste vers une certification.

## Ce qui porte l'empreinte

`threat-model.md` est construit comme une cible Critères Communs, presque terme à
terme :

| Le dépôt | Le vocabulaire CC / ISO 15408 |
|---|---|
| P1–P4, « garantie partielle sans valeur » | Objectifs de sécurité |
| A1–A4, gradués par compétence et outillage | Potentiel d'attaque (élémentaire → élevé) |
| S1–S4, nomenclature normative des tests | Menaces, avec traçabilité exigences↔menaces |
| « Limites assumées », angle mort documenté | Hypothèses sur l'environnement |
| « Toute fonctionnalité doit répondre à une menace identifiée » | La *rationale* d'un PP, mot pour mot |

Même le refus du booléen de confiance et le verdict structuré par propriété sont
des réflexes d'évaluateur : on ne certifie jamais « c'est sûr », on certifie
« résiste à tel attaquant sur tel périmètre ». Le plafond B sur `origin` —
refuser d'affirmer ce qu'on ne sait pas défendre — est exactement ce qu'un CESTI
attend d'une cible honnête.

## Deux nuances

### 1. Le « profil de protection » stricto sensu n'est probablement pas le bon objet

Un PP est un document de *classe de produits*, porté par un industriel ou par
l'ANSSI elle-même, adossé à une évaluation CC complète — lourd, cher, et rare
hors filières établies (cartes, HSM, pare-feux). L'objet ANSSI réaliste pour ce
produit est la **CSPN** (visa de sécurité) : une *cible de sécurité* propre au
produit, de l'ordre de 25–35 jours-homme d'évaluation par un CESTI. Les documents
actuels en sont déjà l'essentiel du contenu — le modèle de menace, la spec
d'enveloppe et les ADR se réassemblent en cible de sécurité à faible coût.

Le point délicat pour une évaluation serait la **définition de la TOE** : la
sécurité repose sur des services tiers non évaluables (Play Integrity, App
Attest), qui deviendraient des hypothèses d'environnement. En revanche, deux
choses jouent en faveur du projet :

- les racines matérielles (TEE, StrongBox, Secure Enclave) sont *elles-mêmes*
  certifiées CC, donc la chaîne de confiance s'arrête sur des composants déjà
  évalués ;
- le client déclaré intégralement hostile est la posture exacte qu'une évaluation
  exige — aucune garantie ne repose sur du code que l'attaquant contrôle.

Parallèle utile : le référentiel **PVID** de l'ANSSI (vérification d'identité à
distance) est l'objet existant le plus proche — mêmes attaques par injection,
rejeu et présentation que les surfaces S2/S3, même problème de preuve captée sur
terminal non maîtrisé. Il montre que l'ANSSI sait normaliser ce type de
scénario… et qu'elle l'a fait par référentiel d'exigences, pas par PP.

### 2. Certification et opposabilité sont deux pistes distinctes

Le dépôt a déjà trouvé la seconde tout seul. Une CSPN dit « ce produit résiste à
un attaquant de tel niveau » ; elle ne donne aucune présomption juridique à la
pièce produite. Ce qui la donne, c'est la piste eIDAS identifiée en
`envelope-spec.md` §9 et `etat-de-l-art.md` §4 : horodatage qualifié, cachet
qualifié, prestataires de la liste de confiance. Le constat que « c'est le seul
manque qu'aucun travail cryptographique ne comblera » est exactement la
frontière entre les deux régimes.

| | Certification (CSPN / CC) | Qualification (eIDAS) |
|---|---|---|
| Affirme | Le produit résiste à un attaquant de niveau donné | La pièce bénéficie d'un statut juridique |
| Porte sur | Le vérificateur et le format, avec les services tiers en hypothèses | Les jetons d'horodatage et de cachet, produits par un prestataire qualifié |
| S'obtient | Évaluation par un CESTI, visa ANSSI | Recours à un prestataire de la liste de confiance — aucune évaluation du produit |
| Dans ce dépôt | Cible de sécurité à écrire (voir ci-dessous) | Spec §9 : deux jetons, nonce à l'émission et enveloppe à la réception |

Un juge s'intéresse aux deux, mais elles ne s'obtiennent pas au même endroit et
ne se bloquent pas l'une l'autre.

## Trajectoire proposée

Non pas « déposer un PP », mais **écrire la cible de sécurité CSPN comme
document du dépôt** :

- peu de travail incrémental, l'essentiel existe déjà ;
- fige le périmètre évaluable — ce qui est affirmé, ce qui est hypothèse
  d'environnement, ce qui est hors périmètre ;
- laisse la porte ouverte à une évaluation le jour où un déploiement le
  justifie, sans en payer le coût avant ;
- pendant que l'opposabilité passe par la piste eIDAS déjà tracée en spec §9.

En somme : comme récit d'origine, l'idée du profil de protection est cohérente
et lisible dans le code — ce dépôt est un modèle de menace *exécutable*, l'inverse
de la plupart des projets, qui écrivent du code d'abord et une justification
ensuite. Comme trajectoire, la forme mûre de cette ambition est la cible de
sécurité, pas le profil.
