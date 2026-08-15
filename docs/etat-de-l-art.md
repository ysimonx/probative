# État de l'art et positionnement

**Vérifié le 2026-08-11, complété le 2026-08-12, passe ciblée le 2026-08-15.** Ce
document périme vite : le marché bouge, et une partie des sources sont commerciales.
Chaque affirmation porte son niveau de confiance ; les liens sont en fin de document.

> **Ajout du 2026-08-12.** Une seconde passe a montré que la première rédaction ratait
> une couche entière — la **valeur juridique**, voir §1 et l'entrée TrueScreen — et deux
> projets libres qui visent exactement notre cible. Rien n'entame le positionnement de
> §3, mais le paysage est plus peuplé que ne le disait la version initiale.

## Pourquoi ce document existe

Trois questions reviennent et méritent une réponse écrite plutôt qu'improvisée : que
font les solutions existantes, en quoi ce dépôt en diffère, et **ce qu'elles font
mieux**. La troisième est la plus utile : un positionnement qui ne concède rien est un
positionnement faux.

---

## 1. Les solutions ne jouent pas toutes sur le même terrain

C'est le point que la comparaison naïve rate. Six couches distinctes se confondent
sous le mot « preuve » :

| Couche | Question à laquelle elle répond | Solutions |
|---|---|---|
| Durcissement du client | Combien coûte l'attaque du binaire ? | Guardsquare |
| Intégrité du canal | Est-ce bien mon application qui appelle mon API ? | Approov |
| **Crédibilité de la revendication** | **Cette image a-t-elle été prise ici, maintenant, par ce capteur ?** | Truepic, OpenOrigins, ProofMode, deux projets libres naissants, **ce dépôt** |
| Interopérabilité de la provenance | Comment cette information circule-t-elle entre outils ? | C2PA / Content Credentials |
| Ancrage et antériorité | Puis-je démontrer que ce contenu existait à cette date ? | Numbers Protocol, horodatage RFC 3161 |
| **Valeur juridique** | **Un tribunal acceptera-t-il cette pièce ?** | TrueScreen (eIDAS), **ce dépôt : rien** |

Seule la troisième ligne est notre terrain. Les autres sont complémentaires — et trois
d'entre elles renforceraient réellement ce dépôt.

Deux couches ont été ajoutées le 2026-08-12. Elles ne sont pas décoratives :

- **L'ancrage** répond à une question que nous ne posons pas. Notre verdict est rendu à
  la réception, ce qui est un choix assumé (§2 sur C2PA) ; il ne dit rien de ce qu'un
  tiers pourra rejouer dans cinq ans.
- **La valeur juridique** est la seule couche où la case « ce dépôt » est vide. Une
  enveloppe au grade `STRONG` n'est pas une signature qualifiée eIDAS, et aucun travail
  cryptographique ne comblera cet écart — il est réglementaire, pas technique.

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

#### Liaison dure, liaison molle — le compromis symétrique du nôtre

*Ajouté le 2026-08-15. Manquait aux deux passes précédentes, et il change la lecture de
toute la section.* Confiance : élevée, sources normatives.

C2PA embarque le manifeste signé **dans** le fichier, en boîte JUMBF. Sa *liaison dure*
est l'assertion `c2pa.hash.data` : un SHA-256 sur les octets exacts, **assorti de zones
d'exclusion**. Ces zones ne sont pas un confort, elles sont mécaniquement obligatoires —
le manifeste vit dans le fichier qu'il hache, et sans elles le hachage devrait s'inclure
lui-même.

**Deux conséquences, opposées.**

D'abord, la question qui nous occupe — conserver les octets — ne se pose pas chez eux :
les octets *sont* la preuve. C'est plus simple à déployer que notre séparation, et il
faut le concéder.

Ensuite, et c'est le renversement : **les zones d'exclusion sont exactement là où
l'article de 2026 a trouvé son trou**, les métadonnées GPS modifiables sans invalider la
signature. Nous n'avons aucune zone d'exclusion, et pas par mérite de conception : c'est
la conséquence mécanique d'ADR-0004, qui garde le manifeste hors du fichier. Le trou et
sa cause sont le même choix d'architecture.

**Le hachage exact casse en distribution**, et c'est admis dans la norme : WhatsApp,
iMessage et Facebook ré-encodent à l'envoi, ce qui invalide silencieusement les Content
Credentials. La réponse est **Durable Content Credentials** (C2PA 2.1 et suivantes) :
au-dessus de la liaison dure s'ajoutent une *liaison molle* — filigrane invisible
(Digimarc, SynthID) et empreinte perceptuelle, tirés d'une liste d'algorithmes
approuvés — et une **copie du manifeste dans une base en ligne**, retrouvable par la
liaison molle quand les octets ont bougé. Une API de liaison molle découplée est
spécifiée.

**Ce que cela vaut pour nous : rien, et il faut savoir dire pourquoi.** Une liaison molle
est probabiliste : elle restaure un *lien*, pas une *preuve*, et rendrait un score de
similarité là où l'invariant 5 exige un verdict par propriété. Surtout, elle répond à la
survie en distribution, quand notre verdict est rendu **à la réception**, avant toute
redistribution. C'est le même classement que l'ancrage de Numbers Protocol : une bonne
réponse à une question que nous ne posons pas — à ne pas confondre avec une lacune.

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

   > **Passe du 2026-08-15 : la revendication ressort affaiblie, pas confirmée.** Une
   > recherche ciblée n'a trouvé **aucune mention** de bruit de capteur, de PRNU ni
   > d'empreinte de capteur dans la documentation publique de Truepic, qui parle de
   > « pixels d'origine » et de scellement C2PA. La technique reste académiquement
   > solide — attribution de source établie de longue date — et **commercialement
   > introuvable**. Pour un différenciateur qui serait évident s'il fonctionnait sur
   > téléphone, c'est un signal : probablement le cumul du coût d'enrôlement, de la
   > forgeabilité documentée et de ce que la photographie computationnelle laisse du
   > résidu. *Confiance abaissée de « moyenne » à « faible » : absence de mention dans
   > des pages promotionnelles, ce qui n'est toujours pas une preuve d'absence, mais
   > deux passes sans rien trouver pèsent davantage qu'une.* Conséquence : ce point 1
   > n'est plus un endroit où Truepic est **établi** devant nous, seulement un endroit
   > où il pourrait l'être. Voir ADR-0007 point 7, qui refuse tout engagement avant
   > trois mesures.

2. **La maturité** : autorité de certification opérée, écosystème C2PA, clients en
   production. Nous n'avons rien de tout cela.

Ce que nous avons et qu'ils n'ont pas : Apache-2.0, auto-hébergeable, sans dépendance à
un service tiers ni à une autorité de certification que nous ne contrôlons pas, et un
verdict gradué par propriété plutôt qu'un manifeste dont la confiance est de fait binaire.

### TrueScreen — le concurrent d'usage, sur une couche que nous n'occupons pas

*Ajouté le 2026-08-12. La première rédaction ne le citait qu'en note de bas de page comme
source secondaire — c'était une erreur d'appréciation.*

Capture forensique (position, identifiants d'appareil, réseau, horodatage), empreinte
cryptographique, **signature électronique avancée conforme à l'article 26 du règlement
eIDAS**, horodatage qualifié **RFC 3161**, et production d'un rapport technique. Le
produit se vend sur son admissibilité devant les juridictions des États membres.

Leurs cas d'usage annoncés sont **exactement les nôtres** : inspection de sinistre,
constat de terrain, protection juridique. C'est le concurrent le plus direct en termes
de marché, bien plus que Guardsquare ou Approov.

**Où nous sommes devant, et l'écart est structurel.** Rien dans leur documentation
publique ne mentionne d'attestation matérielle de plateforme. Leur chaîne établit
« ces octets n'ont pas bougé depuis la certification », jamais « cet appareil n'était
pas compromis au moment de la capture ». Une position simulée sur un téléphone non rooté
produit chez eux une pièce parfaitement certifiée et parfaitement fausse — c'est
précisément la menace qui justifie l'existence de ce dépôt. *Confiance : moyenne, fondée
sur l'absence d'une mention dans des pages promotionnelles, ce qui n'est pas une preuve
d'absence.*

**Où ils sont devant, et l'écart ne se comble pas par du code.** L'admissibilité. Une
signature qualifiée adossée à un prestataire de confiance qualifié a un statut
réglementaire qu'un grade `STRONG` n'aura jamais par ses seules qualités techniques.
Voir §4.

### OpenOrigins (Source) — la formulation la plus proche, la documentation la moins ouverte

*Ajouté le 2026-08-12.* SDK natifs iOS et Android, API REST, signature au moment de la
capture. C'est le seul éditeur trouvé qui revendique explicitement la liaison de
**métadonnées de capture, attestation d'appareil et signature** — la formulation la plus
proche de la nôtre rencontrée sur le marché.

Impossible d'aller plus loin : ni le mécanisme d'attestation, ni l'existence d'un défi
serveur, ni la forme du verdict ne sont publiés. À réexaminer si leur documentation
technique devient accessible. *Confiance : faible — page promotionnelle uniquement.*

### Numbers Protocol (Capture Cam, ProofSnap) — l'ancrage plutôt que le capteur

*Ajouté le 2026-08-12.* C2PA combiné au standard d'indexation de média sur chaîne
ERC-7053, stockage IPFS, frappe de jeton non fongible. Membre de la C2PA.

La confiance y vient de l'**immuabilité d'un registre public**, pas de la crédibilité du
capteur. C'est orthogonal à R1 : ancrer une empreinte démontre l'antériorité d'un
contenu, jamais son origine. Un contenu forgé puis ancré est un contenu forgé
horodaté — c'est d'ailleurs le mode de défaillance que tout système d'ancrage partage.

À retenir tout de même : leur couche répond à une question que nous ne posons pas, celle
du rejeu à long terme par un tiers. Notre verdict est rendu à la réception (choix assumé,
voir la critique de C2PA plus haut) et n'est pas rejouable indéfiniment.

### Attestiv — détection a posteriori, complément et non concurrent

*Ajouté le 2026-08-12.* Analyse par apprentissage automatique d'images **reçues**, sans
aucune coopération du client, produisant un score de falsification par photo. Intégré à
des écosystèmes de gestion de sinistres.

Ce n'est pas un concurrent : ils notent ce qui arrive **sans** enveloppe, nous jugeons ce
qui en porte une. Un déploiement réel aura les deux, parce qu'aucun opérateur ne peut
imposer son application à tous ses correspondants — le flux non instrumenté existera
toujours. Positionner ce dépôt comme un remplacement de ce genre d'outil serait une
erreur de vente autant que d'analyse.

### Deux quasi-clones libres — le fait nouveau

*Ajouté le 2026-08-12. C'est l'information la plus importante de cette passe.*

| | `RoloBits/attestation-photo-mobile` | `VeraSnap` / Content Provenance Protocol |
|---|---|---|
| Cible | React Native, manifeste C2PA incorporé | Android natif, Kotlin et CameraX |
| Clé matérielle | Secure Enclave / StrongBox-TEE | Attestation de clé, `setAttestationChallenge()` |
| Attestation de plateforme | **Aucune** — détection de root heuristique, les auteurs admettent ne pas voir les dissimulateurs | **Aucune** — pas de Play Integrity |
| Défi serveur | Nonce lié à l'empreinte de la photo — **proche de R1** | **Non** — horodatage RFC 3161 à la place |
| Vérificateur | **Aucun** — renvoie vers les outils C2PA génériques | Spécification et vecteurs de test publiés |
| Position | Métadonnée, non corroborée | Coordonnées hachées, aucune preuve de présence revendiquée |
| Maturité | MIT, ordre de la dizaine d'étoiles, quelques dizaines de commits | Phase initiale, plan de développement en cours |

Deux projets embryonnaires — mais la convergence est le signal, pas leur maturité :
**l'idée est dans l'air**, et l'antériorité du code cesse d'être théorique.

Ce qu'aucun des deux ne fait, et qui recoupe exactement notre feuille de route :
confronter la chaîne d'attestation à **la racine publiée par le fabricant** (phase D
côté Apple, phase B côté Google), et rendre un **verdict serveur structuré par
propriété**. L'un et l'autre s'arrêtent à la production d'un artefact signé, en laissant
le jugement à un outil générique ou à un lecteur humain.

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

**Vérification du 2026-08-12 : ces deux points tiennent après élargissement du
périmètre.** Aucun acteur examiné, commercial ou libre, ne **publie** de règle
équivalente à R1. Truepic la pratique très probablement — attestation d'appareil
*avant* capture, et une revendication de détection des attaques par rediffusion — mais
la technique est brevetée et non documentée : ni vérifiable, ni réutilisable. Et aucun
acteur ne rend un verdict gradué par propriété : tous produisent un badge, un score
unique, ou un rapport destiné à un lecteur humain.

Deux réserves d'honnêteté sur cette conclusion. La quasi-totalité des sources sont
promotionnelles, et « personne ne publie R1 » ne veut pas dire « personne ne
l'implémente ».

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
- **Admissibilité juridique** *(ajouté le 2026-08-12)* : c'est le manque le plus net, et
  le seul qu'aucun travail cryptographique ne comblera. TrueScreen vend une signature
  qualifiée eIDAS et un horodatage RFC 3161 auprès d'un prestataire qualifié ; nous
  produisons un verdict techniquement plus exigeant mais sans statut réglementaire. Un
  juge n'a aucune raison *a priori* de préférer notre grade `STRONG`.
- **Ancrage et rejeu à long terme** *(ajouté le 2026-08-12)* : notre verdict est rendu à
  la réception. Les solutions à registre public permettent à un tiers de rejouer la
  vérification des années plus tard, ce que nous ne prévoyons pas.

## 5. Conséquences pour la feuille de route

Rien ici n'invalide le plan en cours, mais cinq inflexions méritent discussion — les
deux dernières ajoutées le 2026-08-12 :

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
4. **Instruire l'horodatage qualifié RFC 3161**, sans préjuger de l'implémenter. C'est le
   seul point où un concurrent offre quelque chose que nous ne savons pas produire, et
   c'est bon marché : une empreinte soumise à une autorité d'horodatage, et une réponse
   conservée à côté de l'enveloppe. Cela n'apporte **aucune** garantie sur l'origine — le
   sujet de ce dépôt — mais rend la pièce opposable dans un cadre où le grade seul ne
   suffit pas. À traiter comme un champ optionnel du noyau, jamais comme une propriété
   notée : le verdict ne doit pas dépendre de la disponibilité d'un tiers, exactement pour
   la raison qui fonde l'invariant n° 3.
5. **Surveiller les deux projets libres.** Aucune urgence technique : ils sont
   embryonnaires et n'ont ni attestation de plateforme ni vérificateur. L'enjeu est
   l'antériorité — d'où l'intérêt de dater les choix dans les ADR et de publier plutôt
   que de garder le dépôt privé.

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

Ajoutées le 2026-08-12 :

- [TrueScreen — plateforme](https://truescreen.io/platform/), [application](https://truescreen.io/app/), [assurance protection juridique](https://truescreen.io/use-cases/legal-protection-insurance/) *(éditeur)*
- [OpenOrigins — Source](https://openorigins.com/products/secure-source) *(éditeur, sans documentation technique publique)*
- [Numbers Protocol — documentation Capture](https://docs.numbersprotocol.io/applications/capture/), [Capture Cam](https://captureapp.xyz/products/capture-cam/), [ProofSnap](https://captureapp.xyz/products/camera/) *(éditeur)*
- [Attestiv dans l'écosystème Duck Creek](https://www.duckcreek.com/resource/in-the-news/attestiv-photo-authenticity-and-fraud-protection-now-available-to-duck-creek-partner-ecosystem/) *(communiqué)*
- [RoloBits/attestation-photo-mobile](https://github.com/RoloBits/attestation-photo-mobile) *(libre, MIT — lu directement, la source la plus fiable de cette passe)*
- [VeraSnap — Content Provenance Protocol](https://dev.to/veritaschain/verasnap-building-a-cryptographic-evidence-capture-app-for-android-with-kotlin-camerax-and-3p2f) *(billet des auteurs)*
- [Truepic Vision — prévention et détection de la fraude](https://www.truepic.com/vision/fraud-prevention-detection) *(éditeur — source de la revendication « plus de 50 contrôles », dont les attaques par rediffusion)*

Ajoutées le 2026-08-15, passe ciblée sur la liaison molle et le PRNU :

- [C2PA — Durable Content Credentials](https://opensource.contentauthenticity.org/docs/durable-cr/) et [Soft Binding API découplée](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html) *(normatif)*
- [C2PA — spécification technique 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html) *(normatif — `c2pa.hash.data`, zones d'exclusion, conteneur JUMBF)*
- [Digimarc — C2PA 2.1 et filigranes](https://www.digimarc.com/blog/c2pa-21-strengthening-content-credentials-digital-watermarks) *(éditeur d'un algorithme de liaison molle approuvé)*
- [Sensor Fingerprints: Camera Identification and Beyond](https://link.springer.com/chapter/10.1007/978-981-16-7621-5_4) *(académique — le PRNU comme technique d'attribution de source)*
- [A Stress Test for Robustness of PRNU Identification on Smartphones](https://pmc.ncbi.nlm.nih.gov/articles/PMC10098672/) *(académique — contre-forensique ; **ne mesure pas** l'effet de la photographie computationnelle, qui reste la question ouverte d'ADR-0007 point 7)*
