# État de l'art et positionnement

**Vérifié le 2026-08-11.** Ce document périme vite : le marché bouge, et une partie
des sources sont commerciales. Chaque affirmation porte son niveau de confiance ; les
liens sont en fin de document.

## Pourquoi ce document existe

Trois questions reviennent et méritent une réponse écrite plutôt qu'improvisée : que
font les solutions existantes, en quoi ce dépôt en diffère, et **ce qu'elles font
mieux**. La troisième est la plus utile : un positionnement qui ne concède rien est un
positionnement faux.

---

## 1. Les solutions ne jouent pas toutes sur le même terrain

C'est le point que la comparaison naïve rate. Quatre couches distinctes se confondent
sous le mot « preuve » :

| Couche | Question à laquelle elle répond | Solutions |
|---|---|---|
| Durcissement du client | Combien coûte l'attaque du binaire ? | Guardsquare |
| Intégrité du canal | Est-ce bien mon application qui appelle mon API ? | Approov |
| **Crédibilité de la revendication** | **Cette image a-t-elle été prise ici, maintenant, par ce capteur ?** | Truepic, ProofMode, **ce dépôt** |
| Interopérabilité de la provenance | Comment cette information circule-t-elle entre outils ? | C2PA / Content Credentials |

Seule la troisième ligne est notre terrain. Les autres sont complémentaires — et deux
d'entre elles renforceraient réellement ce dépôt.

---

## 2. Analyse par solution

### Guardsquare (DexGuard, iXGuard) — durcissement, couche différente

Obfuscation polymorphe multicouche, chiffrement de code et de ressources, et **RASP** :
détection de débogueur, d'émulateur, d'appareil rooté, de frameworks de hook et de
dissimulation de root, épinglage TLS. Le caractère polymorphe est l'argument fort — chaque
build remet à zéro le travail d'un attaquant.

**Rapport à ce dépôt.** Aucune concurrence : Guardsquare ne produit aucun artefact
vérifiable par un tiers. Notre invariant n° 1 pose le client comme hostile *par
principe*, donc la garantie ne doit jamais reposer sur le durcissement.

**Mais c'est le renfort le plus pertinent que nous ayons identifié.** Notre champ
`posture` fait une détection artisanale (débogueur, émulateur, position simulée) là où
DexGuard fait le même travail avec des années d'avance, notamment sur les frameworks de
hook — qui sont précisément le vecteur de l'injection de trames. Un déploiement exigeant
gagnerait à combiner les deux : eux durcissent le chemin, nous produisons la preuve.

### Approov — attestation d'application, couche différente

Enregistrement d'une signature de l'application auprès d'un service infonuagique ; avant
chaque appel d'API, le SDK et le service évaluent l'application et son environnement, et
émettent un jeton signé de courte durée (mis en cache ≤ 5 min). L'argument de conception
est bon : **aucun secret n'est embarqué dans l'application**, donc rien à extraire par
rétro-ingénierie.

**Rapport à ce dépôt.** Approov protège le *canal* et l'*appelant*, pas le *contenu*. Il
répond « est-ce bien mon application ? », jamais « cette image a-t-elle été prise ici ».
Un jeton Approov valide accompagnant une image injectée reste valide.

C'est exactement la confusion que la **règle R1** existe pour empêcher : attester qu'un
appareil sain existe *à côté* du contenu ne prouve rien. Approov est conceptuellement
proche de ce que fait Play Integrity dans notre pipeline — une brique de fraîcheur —, pas
un substitut à la liaison.

### C2PA / Content Credentials — norme d'interopérabilité, et son procès

C2PA est un **format de manifeste signé** décrivant la provenance et l'historique
d'édition. Spécification 2.3 en janvier 2026, 2.4 en avril 2026, avec un programme de
conformité définissant des niveaux d'assurance.

L'adoption a franchi un cap, et c'est le fait stratégique le plus important de ce
document :

- **Pixel 10 Pro** : *toute* photo prise avec l'appareil photo natif est signée par
  défaut, sans réglage ni compte (Tensor G5 + Titan M2). Il atteint le **niveau
  d'assurance 2**, le plus élevé actuellement défini par le programme de conformité.
- **Galaxy S25** : logique inverse et discutable — seules les images **retouchées par
  IA** portent des Content Credentials. Les photos authentiques non modifiées circulent
  donc sans marqueur.

**La critique académique est sévère et nous concerne directement.** Un article de 2026
conclut que « les spécifications et les implémentations C2PA n'atteignent aucun des
objectifs de sécurité revendiqués », avec notamment :

| Faille C2PA relevée | Ce que fait ce dépôt |
|---|---|
| **Rien dans les données signées ne référence l'horodatage** — il peut être remplacé sans détection | L'instant est dans la charge utile signée, et lié au défi serveur (R1) ; le nonce empêche le rejeu |
| Des **zones d'exclusion** laissent modifier certaines régions, dont les **métadonnées GPS**, sans invalider la signature | Il n'existe pas de zone d'exclusion : la position est un champ de la charge utile, entièrement couvert par la signature |
| Vérification de **révocation optionnelle** | La clé est adossée au matériel et enrôlée ; la chaîne d'attestation est validée côté serveur (phase B) |
| **Validateurs incohérents** entre eux | Le verdict est rendu par un vérificateur unique, avec un résultat structuré par propriété |
| Contenus **invérifiables à l'expiration** du certificat | Le jugement est rendu à la réception, pas indéfiniment rejouable |

Ces points ne sont pas un argument contre C2PA — ils disent que C2PA résout
l'*interopérabilité*, pas la *crédibilité*. Les deux se composent, et §9 de
`envelope-spec.md` prévoit déjà l'alignement C2PA en v0.3. Ce document conforte ce choix
d'ordre : d'abord la liaison dure, ensuite l'emballage interopérable.

### ProofMode (Guardian Project + WITNESS) — le plus proche en esprit

Application et protocole **open source** ajoutant à la capture des signatures
cryptographiques, une notarisation par tiers, une **authentification matérielle** et des
métadonnées corroborantes. La version 3.x est pleinement conforme **C2PA 2.3**. Orienté
documentation des droits humains, avec un souci de vie privée et de faible friction.

**Rectification.** ProofMode ne se limite plus à une signature logicielle post-capture :
l'authentification matérielle fait partie de ses fonctions annoncées. La différence
tenable ne porte donc pas sur « matériel ou pas », mais sur :

- **la liaison au défi serveur** : ProofMode privilégie une chaîne de possession
  décentralisée et notariée, sans nonce serveur — cohérent avec son modèle d'usage, où
  l'appareil peut être hors ligne et où l'on ne veut dépendre de personne ;
- **le jugement** : ProofMode fournit des preuves à un lecteur humain ou à un juriste,
  là où ce dépôt rend un **verdict structuré par propriété**, exploitable par un système.

Ce sont deux réponses légitimes à deux contraintes différentes. ProofMode est la
référence à connaître pour tout ce qui touche la notarisation et le hors-ligne.

### Truepic (Lens) — le vrai concurrent

SDK remplaçant l'appareil photo natif pour empêcher l'altération, signature du contenu
sur l'appareil en Content Credentials, autorité de certification propre, génération de
clé et délivrance de certificat intégrées. Truepic revendique une sécurité **supérieure à
la spécification C2PA seule**, avec attestation et confirmation d'intégrité de
l'appareil. Premier à prendre en charge C2PA 2.0 en entreprise.

Deux points où Truepic est devant :

1. **La liaison au capteur physique.** Truepic et Leica combineraient horodatage signé en
   enclave sécurisée et **empreinte de bruit de capteur** (PRNU) pour lier une photo à un
   exemplaire d'appareil donné. *Source secondaire, à confirmer.*

   > **Correction du 2026-08-11.** Une première rédaction de ce document affirmait que
   > cette technique répondait à notre angle mort. **C'est faux**, et
   > `screen-capture-detection.html` le disait déjà : si l'attaquant photographie un écran
   > *avec l'appareil enrôlé*, le capteur enrôlé a réellement formé l'image, donc son PRNU
   > est présent et corrèle. Le PRNU répond à « quel capteur a formé cette image », jamais
   > à « qu'y avait-il devant l'objectif ». Ce à quoi il répond vraiment, et qui nous
   > intéresse, est **l'injection de trames** : caméra virtuelle, fichier pré-enregistré
   > ou image générée ne portent pas le PRNU attendu. C'est une liaison au matériel fondée
   > sur le contenu et *indépendante de la clé* — elle tiendrait même si le chemin de
   > signature légitime était détourné pour signer des octets étrangers.

2. **La maturité** : autorité de certification opérée, écosystème C2PA, clients en
   production. Nous n'avons rien de tout cela.

Ce que nous avons et qu'ils n'ont pas : Apache-2.0, auto-hébergeable, sans dépendance à
un service tiers ni à une autorité de certification que nous ne contrôlons pas, et un
verdict gradué par propriété plutôt qu'un manifeste dont la confiance est de fait binaire.

---

## 3. Ce qui distingue réellement ce dépôt

Deux points, pas dix.

1. **La règle R1.** Le défi soumis au service d'attestation vaut exactement
   `SHA-256(payload_bytes ‖ nonce)`. Beaucoup d'intégrations attestent « un appareil sain
   existe » *à côté* du contenu, sans lier les deux — ce qui ne prouve rien. La critique
   académique de C2PA sur l'horodatage non couvert par la signature est la même erreur,
   commise dans une norme.
2. **Le serveur juge, propriété par propriété.** Pas de badge « vérifié », mais quatre
   grades et un `level_reason` exploitable en support. L'incohérence entre validateurs
   relevée chez C2PA découle directement de l'absence d'arbitre unique.

S'y ajoute, sans être un différenciateur technique : licence Apache-2.0 avec concession
de brevet, auto-hébergement complet, aucune dépendance de service à l'exécution.

## 4. Ce qu'ils font mieux — à assumer

- **Photographie d'écran** : non détectée ici, plafonnée au grade B. L'écart est
  d'**implémentation, pas d'analyse** : `screen-capture-detection.html` recense déjà cinq
  familles de signaux, dont le défi actif dérivé du nonce. Rien n'indique qu'un concurrent
  ait résolu cette menace — et surtout pas le PRNU, qui ne s'y applique pas (voir §2).
- **Interopérabilité** : un manifeste C2PA se lit dans tout l'écosystème. Notre enveloppe
  ne se lit que par notre vérificateur.
- **Le socle bouge sous nos pieds** : quand un Pixel 10 signe *toutes* ses photos
  nativement au niveau d'assurance 2, la valeur d'un SDK de capture tierce diminue sur ce
  segment. Notre valeur se déplace vers ce que le natif ne fait pas — la liaison à un
  défi serveur, la corroboration de position, et le verdict gradué.
- **Durcissement** : notre `posture` est artisanale à côté d'un RASP commercial.
- **Maturité** : aucun historique d'exploitation, aucune autorité de certification opérée.

## 5. Conséquences pour la feuille de route

Rien ici n'invalide le plan en cours, mais trois inflexions méritent discussion :

1. **Étudier l'empreinte de bruit de capteur (PRNU) contre l'injection de trames** — et
   non contre la photographie d'écran, voir la correction en §2. L'intérêt est réel et
   distinct de ce que nous avons : une liaison au capteur *fondée sur le contenu*, qui
   survivrait à un détournement du chemin de signature, là où `media[6]` ne mesure qu'une
   latence. Coût à instruire : l'enrôlement exige plusieurs images de référence par
   appareil, et le calcul est côté serveur.

   La photographie d'écran, elle, reste traitée par les cinq familles de
   `screen-capture-detection.html` — le défi actif dérivé du nonce en étant la plus
   solide, et la plus cohérente avec nos invariants puisqu'elle réutilise un nonce serveur
   à usage unique déjà présent dans le format.
2. ~~Confirmer l'alignement C2PA en v0.3~~ — **tranché le 2026-08-11, voir
   [ADR-0004](decisions/ADR-0004-c2pa-passerelle.md).** Passerelle et non remplacement,
   avec deux précisions que la rédaction de ce document avait manquées : le manifeste est
   produit **côté serveur, après le verdict** (le certificat de signature ne descend
   jamais sur les appareils, et le manifeste peut alors exprimer le résultat de la
   vérification — ce qu'un manifeste produit sur l'appareil ne pourrait pas faire, puisque
   l'appareil ne juge pas) ; et `media[2]`/`media[4]` désignent définitivement les octets
   bruts du capteur, car un manifeste incorporé change les octets du fichier et créerait
   une dépendance circulaire. Point à instruire hors code : signer un manifeste C2PA exige
   un certificat inscrit dans la liste de confiance du programme de conformité.
3. **Documenter la complémentarité avec un RASP commercial** plutôt que de chercher à le
   réimplémenter. Un déploiement exigeant combinera les deux.

---

## Sources

Fiabilité inégale : les sources d'éditeurs sont promotionnelles, les billets tiers sont
secondaires. Le seul travail critique et indépendant est l'article arXiv.

- [Approov — How does Approov work?](https://approov.io/knowledge/how-does-approov-work) et [Mobile App Attestation](https://approov.io/mobile-app-security/rasp/app-attestation/) *(éditeur)*
- [Guardsquare — DexGuard](https://www.guardsquare.com/dexguard) et [Protecting Android Applications and SDKs](https://www.guardsquare.com/protecting-android-applications-and-sdks) *(éditeur)*
- [Truepic — Capture C2PA](https://www.truepic.com/c2pa/capture), [Truepic first with C2PA 2.0 support](https://www.truepic.com/blog/truepic-first-with-c2pa-2-0-support-for-enterprises), [Lens — Understand C2PA](https://lens.truepic.dev/docs/c2pa-overview) *(éditeur)*
- [ProofMode et C2PA](https://proofmode.org/c2pa), [Guardian Project — Proofmode and C2PA](https://guardianproject.github.io/info/code/c2pa/), [dépôt Android](https://github.com/guardianproject/proofmode-android) *(éditeur, open source)*
- [Verifying Provenance of Digital Media: Why the C2PA Specifications Fall Short](https://arxiv.org/html/2604.24890v1) *(travail académique indépendant — la source la plus solide de ce document)*
- [Content Credentials on Smartphones: What's Available in 2026](https://c2pa.ai/smartphone-guide), [Google Pixel 10 C2PA Content Credentials](https://c2paviewer.com/articles/google-c2pa-pixel-10), [C2PA Adoption in 2026 Hardware Platforms](https://www.softwareseni.com/c2pa-adoption-in-2026-hardware-platforms-and-verification-reality/) *(sources secondaires)*
- [What Is C2PA? The Standard, Its Metadata and Real Limits](https://truescreen.io/articles/c2pa-standard-history-limitations/) *(source secondaire, éditeur concurrent)*
