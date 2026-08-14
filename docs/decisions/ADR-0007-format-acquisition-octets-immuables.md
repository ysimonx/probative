# ADR-0007 — Format d'acquisition declare, octets scelles immuables

**Statut :** accepte
**Date :** 2026-08

## Contexte

Le format du payload acquis n'a jamais ete decide. Il a ete **herite**, en ecrivant C4.2
le 2026-08-13, et il est aujourd'hui inscrit en dur a trois endroits du coeur iOS qui ne
se parlent pas :

- `Camera.swift` demande explicitement `AVVideoCodecType.jpeg`. Ce n'est pas le defaut
  d'iOS — un appareil recent produit du HEIC si on ne dit rien — c'est donc une deviation
  active, et elle n'est motivee nulle part.
- `Sealer.swift` ecrit la chaine litterale `"image/jpeg"` dans `media[3]`.
- Le type public `CapturedImage` nomme son champ `jpeg`.

**Rien ne relie ces trois points.** Changer le codec dans `Camera.swift` laisserait
`Sealer.swift` annoncer `image/jpeg` pour des octets HEIC : l'enveloppe declarerait un
type faux, **signe**, opposable, et rien ne le verrait. Aucun test ne confronte les deux,
et le verificateur ne le peut pas — l'invariant 6 lui interdit de connaitre le type de
contenu. C'est le mode de defaillance decrit en §2.4 a propos des unites : rien ne casse,
la donnee est simplement fausse, et aucun verdict ne le signale.

Le troisieme point aggrave les deux premiers. Le format est dans le **nom d'un champ
d'API publique** : en changer ne serait pas un reglage, ce serait une rupture d'interface.

**A4.2 n'est pas ecrite.** Android n'a donc rien choisi. Dans l'etat, la capture CameraX
reproduira le meme codage en dur une quatrieme fois, ou divergera en silence — et c'est
la raison pour laquelle cette decision se prend maintenant plutot qu'apres.

**Le choix n'est pas neutre a long terme**, pour un motif etranger a la photographie.
L'empreinte de bruit de capteur (PRNU), instruite dans `frame-injection.html` couche 3,
est la seule piste connue contre l'**injection de trames** — precisement la faiblesse que
la specification §2.5 reconnait quand elle ecrit que l'acquisition par le coeur « ne
prouve pas l'origine capteur ». Or le PRNU se degrade avec la compression, le recadrage,
le redimensionnement et le debruitage.

## Decision

1. **JPEG reste le format du chemin d'acquisition en v0.1**, et le motif est desormais
   ecrit : **la lisibilite a long terme prime sur la compacite et sur la finesse du
   residu de bruit.** Une piece destinee a etre opposee dans dix ans se conserve dans le
   format qu'on saura ouvrir dans dix ans.

2. **Le format sort du nom des types publics.** Le champ de `CapturedImage` prend un nom
   neutre, et le type porte son propre type MIME au lieu de le laisser deviner.

3. **`media[3]` derive du format reellement encode, jamais d'une chaine parallele.** Une
   seule source de verite, du reglage du codec jusqu'a l'enveloppe.

4. **Le coeur ne re-encode jamais.** Les octets haches sont ceux que le pipeline photo a
   produits, et ce sont ces memes octets qui sont transmis. La regle existait en
   commentaire dans `Camera.swift` ; elle devient normative et vaut pour les deux
   plateformes.

5. **La conservation des octets, intacts, incombe a l'integrateur, et la specification
   doit le dire.** L'enveloppe ne porte qu'une empreinte : sans les octets, le verdict
   sur le contenu ne vaut rien. Toute transformation — recompression, nettoyage d'EXIF,
   normalisation d'orientation, redimensionnement, injection d'un manifeste dans le
   fichier — rompt la liaison sans rattrapage possible. Les derives se fabriquent **a
   cote**, jamais a la place.

6. **Le PRNU ne repond pas a la recapture analogique, et cette correction est
   definitive.** Il repond a « quel capteur a forme cette image », jamais a « qu'y
   avait-il devant l'objectif ». Le plafond `origin` <= B du profil `capture` n'est donc
   pas levable par cette voie.

7. **Aucun engagement sur le PRNU avant trois mesures**, dans cet ordre : ce que le
   pipeline computationnel laisse du residu ; si la SM-X200 sait produire du DNG via
   Camera2 ; le cout en `media[6]` et en bande passante. Tant qu'elles manquent, le PRNU
   reste une piste v0.3 et non une contrainte de conception.

## Justification

- **Le point 3 est le seul enjeu de correction de cet ADR.** Les autres organisent ou
  documentent ; celui-la ferme un chemin par lequel une enveloppe signee peut mentir. Le
  type MIME est declaratif, comme `posture` : sa sincerite n'est pas verifiee, et ne peut
  pas l'etre sans violer l'invariant 6. Un champ declaratif que le client peut fausser
  **par accident** est une categorie a part de celui qu'un attaquant fausse
  deliberement — le second est prevu par le modele de menace, le premier n'est prevu par
  personne.
- **Le point 2 preserve une option sans la payer.** Le format est declare par capture
  dans `media[3]` : une v0.3 peut ajouter un chemin RAW sans casser une seule enveloppe
  v0.1, ni ouvrir un profil — §2.5 point 4 l'interdit explicitement pour un simple
  changement de type MIME. La seule chose qui rendrait ce virage couteux est un nom de
  type public qui grave le format dans l'interface. C'est donc la, et uniquement la, que
  la dette se paie aujourd'hui.
- **Le point 1 ne repose pas sur la qualite d'image.** JPEG perd de l'information et
  degrade le residu de bruit ; c'est admis. L'argument est l'opposabilite : un format
  universellement lisible, sans pari sur la disponibilite d'un decodeur, pour une piece
  dont toute la valeur est d'etre presentable a un tiers longtemps apres.
- **Le point 7 refuse de trancher par assertion une question technique ouverte.** Un
  iPhone 16 ne rend pas une lecture brute du capteur : fusion multi-images, HDR,
  debruitage par reseau de neurones. Le debruitage est precisement ce qui detruit le
  PRNU — il est possible que le residu soit deja compromis **avant** l'encodeur, auquel
  cas passer a un format sans perte n'achete rien et seul le bayer RAW aurait un sens.
  Apple ProRAW ne suffirait pas : il est demosaique et traite. Rien de tout cela n'est
  mesure a ce jour, et un ADR qui l'affirmerait dans un sens ou dans l'autre inventerait
  une donnee.

  **Aucun precedent commercial n'a ete trouve.** *Verifie le 2026-08-15.* La
  documentation publique de Truepic parle de « pixels d'origine » et de scellement C2PA,
  jamais de bruit de capteur ; la revendication PRNU rapportee dans `etat-de-l-art.md`
  reposait sur une source secondaire et ressort **affaiblie** de cette passe. Le PRNU est
  solide academiquement et absent des produits. Pour une technique qui serait un
  differenciateur evident si elle marchait sur telephone, c'est un signal — probablement
  le cumul du cout d'enrolement, de la forgeabilite documentee et du pipeline
  computationnel. Cela ne prouve rien, et c'est bien pourquoi le point 7 exige des
  mesures plutot qu'une conclusion.
- **Le point 6 est ecrit parce que l'erreur a deja ete commise.** `etat-de-l-art.md`
  porte une correction datee du 2026-08-11 sur exactement ce point, apres une premiere
  redaction qui presentait le PRNU comme la reponse a l'angle mort. Une confusion qui
  revient merite une decision, pas une seconde note de bas de page.
- **Le point 5 n'est pas une precaution d'usage : c'est la contrepartie d'ADR-0004.**
  *Verifie le 2026-08-15.* Le marche fait l'inverse — C2PA, donc Truepic, ProofMode 3.x
  et le Pixel 10, embarque le manifeste signe **dans** le fichier, en boite JUMBF. La
  question de conserver les octets ne s'y pose pas : les octets *sont* la preuve. Nous
  avons choisi l'inverse, et cela se paie exactement ici.

  Le contraste vaut mieux qu'un argument abstrait, parce qu'il montre ce que chaque
  camp achete. Leur assertion `c2pa.hash.data` hache les octets exacts **avec des zones
  d'exclusion** — mecaniquement obligatoires, le manifeste vivant dans le fichier qu'il
  hache. Or ces zones d'exclusion sont precisement ou l'article de 2026 cite en
  `etat-de-l-art.md` a trouve son trou : metadonnees GPS modifiables sans invalider la
  signature. **Nous n'avons aucune zone d'exclusion, et pas par vertu** : c'est la
  consequence mecanique de garder l'enveloppe dehors. Le prix de cette absence de trou
  est l'obligation de conservation, et il faut l'assumer comme tel plutot que le
  presenter comme une consigne d'integration.

  La specification §6 pose deja qu'une enveloppe archivee doit rester verifiable des
  annees plus tard, mais uniquement a propos du canal : rien n'enonce l'obligation
  symetrique sur les octets. Le drapeau `MEDIA_NOT_PROVIDED` signale l'absence des
  octets a la verification ; il ne dit rien de leur perte definitive, qui est
  irrattrapable.

## Consequences

- **Trois modifications du coeur iOS**, toutes sans effet sur le format d'enveloppe :
  renommer le champ de `CapturedImage`, lui faire porter son type MIME, et faire lire ce
  MIME par `Sealer` au lieu de la chaine litterale. Aucun vecteur d'or n'est touche : ils
  restent en `image/jpeg`, valeur inchangee.
- **A4.2 herite de la decision au lieu de la refaire.** La capture CameraX declare son
  format par le meme mecanisme, et le test d'hote qui epingle Kotlin au vecteur d'or
  couvre de fait la coherence des deux plateformes.
- **La specification §2.3 recoit un paragraphe normatif** sur la conservation des octets,
  a cote de `media`. C'est le seul changement documentaire impose par cet ADR, et il ne
  touche ni le CDDL ni la notation.
- **Un test manque, et il est nomme ici plutot qu'omis** : rien ne verifie que le MIME
  declare correspond au codec configure. Le point 3 rend le defaut impossible par
  construction cote iOS, ce qui vaut mieux qu'un test — mais la garantie disparaitrait au
  premier chemin d'acquisition qui contournerait le mecanisme.
- **Le PRNU entre dans les inconnues de `CLAUDE.md`** avec ses trois mesures prealables,
  au lieu de rester une ligne du journal du spike. Il ne deplace ni A4.2, ni la phase B.
- **Aucun effet sur `origin`.** Le plafond de recapture reste en dur (`RECAPTURE_CAP`),
  conformement a la regle « une option peut resserrer, jamais desserrer un angle mort
  assume ». Le point 6 confirme qu'aucune des pistes de cet ADR ne le leve.

## Ce qui ferait revenir sur cette decision

Si les trois mesures du point 7 montraient que le residu de bruit survit au pipeline
computationnel et que le DNG est disponible sur les deux plateformes cibles, le format
par defaut redeviendrait discutable : un chemin d'acquisition RAW optionnel, reserve aux
deploiements qui acceptent son cout de bande passante, se justifierait alors — sans
remplacer JPEG, qui resterait le defaut pour la meme raison de lisibilite.

Si l'injection de trames cessait d'etre une menace credible — parce que les deux
plateformes fermeraient l'acces des cameras virtuelles aux applications attestees — le
point 7 deviendrait sans objet et le format se deciderait sur la seule opposabilite.

Si a l'inverse un besoin de compacite devenait dimensionnant, HEIC se substituerait a
JPEG par simple changement de `media[3]`, sans nouveau profil. C'est le point 2 qui rend
ce virage bon marche ; sans lui, il coute une rupture d'API.
