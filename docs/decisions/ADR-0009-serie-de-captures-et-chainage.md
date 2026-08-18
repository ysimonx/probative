# ADR-0009 — Serie de captures : tete attestee, maillons chaines, largeur mesuree

**Statut :** accepte, **amende le 2026-08-17** (points 1, 5 et 7) et **le 2026-08-18** (« la visite ») ; **point 2 abandonne** par ADR-0010
**Date :** 2026-08

## Contexte

Une prise isolee n'a rien a chainer. Une **serie** — plusieurs captures d'un meme
constat — a deux proprietes qu'une suite de prises independantes n'a pas : un **ordre**,
et l'**absence de retrait**. Rien dans le format ne les etablit aujourd'hui.

Le mecanisme existe pourtant a moitie. `payload[7]` porte l'empreinte de l'enveloppe
precedente (spec §9), le verificateur le confronte a `DeviceRecord.last_envelope_digest`,
en tire `chain_verified`, et `grade_time` promeut alors `time` en A par
`envelope-chain-verified`. Ce qui manque n'est pas la plomberie, c'est **ce qu'une serie
signifie**.

**Un fait mesure a rendu la question urgente.** Le 2026-08-17 sur SM-X200, cinq campagnes
en vingt secondes ont declenche le bridage de Play Integrity — `Standard Integrity API
error (-8)`, puis huit echecs d'affilee. Une serie Android ne peut donc pas demander un
jeton de fraicheur par prise a cadence libre.

**Ce fait ne doit pas etre la justification de cette decision, et le distinguo est le
coeur de cet ADR.** Un quota de fournisseur releve de l'exploitation : il change sans
preavis, differe d'un compte a l'autre, et la regle du depot est que ce qui change
l'exploitation se configure quand ce qui change le format se tranche. Concevoir le format
autour d'un quota Google reviendrait a graver une contrainte commerciale dans une
specification censee survivre a son fournisseur.

La serie se justifie par ce qu'elle **prouve** : qu'aucune prise ne manque. Le bridage
n'est qu'une des raisons pour lesquelles N captures independantes ne conviennent pas ; ce
n'est pas la meilleure.

**Deux contraintes de format encadrent la solution.** `freshness` est **obligatoire** au
CDDL (`200 => freshness`, sans `?`), et il vit dans l'en-tete **non protege** — donc non
couvert par la signature. `payload[7]`, lui, est dans la charge utile signee.

## Decision

1. ~~**Une serie est une tete attestee, des maillons chaines, et une queue attestee.**~~
   **Amende.** Une serie est une **tete attestee** et des **maillons chaines**. Une
   enveloppe attestee qui survient ensuite -- « queue » explicite, ou simplement la
   premiere prise d'une nouvelle serie -- **resserre** la note des maillons qui la
   precedent, mais n'est pas une condition de validite. Les maillons portent `payload[7]`
   et rien d'autre.

2. ~~**`freshness` devient optionnel**~~ — **ABANDONNE le 2026-08-17, ADR-0010.** Deux
   mesures du meme jour ont retire a ce desserrage ses deux justifications. Le bridage
   venait des `prepare` repetes et non des demandes de jeton : la fraicheur par enveloppe
   tient a la cadence reelle en ligne, ce qui est exactement la clause de reouverture
   ecrite plus bas. Et le hors ligne, seule justification restante, trouve une meilleure
   reponse — un **troisieme type** de preuve de fraicheur, `key-attestation`, produit par
   la puce sans reseau et portant R1 intacte. Le format se resserre au lieu de se
   desserrer, et `freshness` reste obligatoire.

3. **Un maillon ne transporte pas un jeton qui ne le lie pas.** Reutiliser tel quel le
   jeton de la tete etait l'autre voie : elle est refusee. Un jeton dont le `requestHash`
   ne couvre pas cette charge utile **ressemble** a une attestation sans en etre une, et
   R1 n'est pas negociable (invariant 2). Mieux vaut une absence declaree qu'une preuve
   d'apparence.

4. **Aucun identifiant de session dans le format.** Le rattachement d'une enveloppe a sa
   serie est `payload[7]`, cryptographique et **signe**. Un identifiant declare par le
   client serait de la famille de `posture` : falsifiable, et ne prouvant aucun
   rattachement. C'est aussi pourquoi la declaration de serie ne peut pas vivre dans
   l'en-tete non protege.

5. **`integrity` sur un maillon est plafonne, sous le grade d'une enveloppe fraichement
   attestee**, avec un motif qui nomme la raison. Le chainage prouve l'ordre, jamais la
   sante continue de l'appareil.

   **Amende :** le plafond n'est pas un palier unique mais une note sur la **largeur
   observee** -- la distance, mesuree par le serveur sur ses propres emissions de nonce,
   entre la derniere enveloppe attestee et ce maillon. Un maillon a quinze secondes de sa
   tete ne vaut pas un maillon a trois heures, et le grade doit suivre continument.

6. **`time` sur un maillon garde le benefice du chainage.** `envelope-chain-verified`
   promeut deja `time` en A, et c'est correct : l'ordre est exactement ce que la chaine
   etablit.

7. ~~**Une serie sans queue attestee est signalee.**~~ **Amende : il n'y a rien a
   signaler.** La fenetre est **deja bornee et mesuree**, parce que le serveur emet un
   nonce **par enveloppe**, y compris pour les maillons. Chaque maillon est donc encadre
   par la propre horloge du serveur, sans qu'aucune declaration du client n'intervienne.
   Le point 5 amende note cette largeur ; il n'y a pas de drapeau supplementaire.

## L'amendement du 2026-08-17, et pourquoi

La question posee etait : « puisqu'une serie dure deux minutes au plus, la queue est-elle
utile ? »

**La reponse par les deux minutes est fausse**, et il faut le dire avant le reste : ce
plafond est une politique **du client**, et le client est hostile par hypothese. Rien
n'oblige un attaquant a clore, et le verificateur ne saurait pas qu'une serie « devait »
s'arreter.

**Mais la conclusion est juste, par un autre chemin.** Le serveur emet un nonce par
enveloppe, maillons compris. Un nonce donne un encadrement bilateral -- la capture est
posterieure a son emission, anterieure a sa reception. Le serveur **mesure donc lui-meme**
la distance entre la derniere attestation et chaque maillon, avec sa propre horloge et
sans rien croire du client.

La queue n'etait donc pas necessaire pour borner la fenetre : elle l'etait deja. Ce que la
queue apporte est un **second controle de sante**, utile mais pas indispensable -- donc un
resserrement, pas une exigence.

**C'est exactement la correction deja faite ailleurs.** Le 2026-08-15, `grade_time` notait
sur `offline: bool`, un mode *declare*, et fut remplace par `max_nonce_window_ms`, qui note
sur la largeur *observee*. La justification tenait en une phrase : un seuil sur une duree
de vie declaree aurait puni un lot consomme aussitot. Ici, « serie close ou non » etait le
drapeau declare ; « distance depuis la derniere attestation » est la grandeur mesuree.

Trois choses tombent avec cet amendement :

- **l'enveloppe de cloture supplementaire.** Elle etait rendue necessaire par le fait
  qu'on ne sait pas a l'avance quelle photo sera la derniere -- une queue ne pouvant pas
  etre attestee apres coup, R1 portant sur sa propre charge utile. La question de ce
  qu'elle aurait scelle est sans objet ;
- **le geste obligatoire.** Bouton, minuterie et passage en arriere-plan deviennent des
  moyens de *resserrer* la note, jamais des conditions de validite ;
- **le benefice pour l'attaquant de ne pas clore.** Il n'y en a aucun : sa chaine s'eloigne
  de son attestation et le grade tombe de lui-meme.

## Justification

- **Le point 1 est l'encadrement bilateral, applique a une serie.** C'est la meme figure
  que le nonce donne deja au temps : la charge utile le contient donc la capture lui est
  posterieure, le serveur l'a recue avant expiration donc elle lui est anterieure. La
  chaine ajoute a cet encadrement, valable enveloppe par enveloppe, l'impossibilite
  d'inserer, de retirer ou de reordonner — et R2 continue de prouver **quel appareil** a
  chaque maillon.

  *Amende : la redaction d'origine parlait de « deux points attestes bornant la serie des
  deux cotes ». C'etait vrai mais superflu — chaque maillon porte deja son propre nonce,
  donc son propre encadrement. La borne ne vient pas de la queue.*

- **Le point 5 est ce qui rend le point 2 acceptable plutot que complaisant.** Un
  attaquant qui obtient une tete attestee puis compromet l'appareil peut produire des
  maillons suivants : la chaine ne s'en apercevra pas. C'est la faiblesse exacte de cette
  decision, et elle est payee par le grade, pas dissimulee. Ce qui la borne n'est pas une
  queue mais la **mesure** : le serveur sait de combien ce maillon s'est eloigne de la
  derniere attestation, et note en consequence.

- **Le point 3 refuse la solution qui aurait ete la plus simple a coder.** Un jeton
  reutilise passerait les controles de forme et echouerait a R1, ce qui obligerait le
  verificateur a distinguer « jeton absent » de « jeton present mais non liant » — deux
  chemins pour un meme fait, dont l'un a l'apparence d'une preuve. Le depot a deja paye
  ce genre d'ambiguite avec le type MIME parallele (ADR-0007 point 3).

- **Le point 4 tient a ou vivent les champs.** `payload[7]` est signe ; l'en-tete de
  fraicheur ne l'est pas — c'est la meme faiblesse que le compteur d'assertion, relevee
  en phase D. Une declaration qui change la notation ne peut pas vivre dans un champ que
  n'importe qui reecrit.

- **Rien de tout ceci n'est propre a une plateforme.** App Attest n'a ni reseau ni quota,
  mais une serie iOS a exactement le meme besoin d'ordre et d'absence de retrait. Le
  format decrit donc une serie, jamais un contournement Android — invariant 4.

- **Le cadrage par la preuve plutot que par le quota a une consequence pratique
  immediate** : si Google relevait ses quotas demain, la serie resterait justifiee. Si
  elle avait ete concue pour les contourner, elle deviendrait un residu qu'on n'oserait
  plus retirer.

## Amendement du 2026-08-18 — la visite, et ce qu'une serie ne couvre pas

Le terrain visé a répondu à une question que cet ADR n'avait pas posée : **une visite de
chantier est constituee de plusieurs campagnes de prises de photos**, et non d'une seule.
Trois consequences, dont une lacune.

13. **Une serie = une campagne, jamais une visite.** Une campagne au sens d'ADR-0011 : un
    lot de nonces, une chaine, un ensemble valide ensemble. L'operateur en ouvre une par
    sujet ou par zone, et la clot en changeant. Les bornes automatiques — compteur, duree —
    sont donc des **filets de securite** qui ne doivent pas se declencher en usage normal,
    et non des unites de decoupe. Portees a 100 prises et deux heures cote sonde.

14. **La mise en veille ne clot rien.** Elle avait ete traitee comme le geste implicite
    « j'ai fini ». C'est faux : sur un chantier, l'operateur met son telephone en veille
    **entre deux points de la meme campagne**. Clore la fragmenterait la chaine sans qu'il
    l'ait voulu, et l'absence de retrait ne vaudrait plus que sur chaque morceau. Un
    evenement systeme n'est pas une intention ; seul le bouton l'est.

15. **Rien ne relie deux campagnes d'une meme visite — c'est une lacune, et elle est
    assumee pour l'instant.** L'absence de retrait tient *a l'interieur* d'une campagne.
    Retirer une campagne entiere du dossier de visite est **invisible** : aucune empreinte
    ne franchit la frontiere. C'est le meme defaut de forme que la fragilite du repli
    d'ADR-0011 point 5, un cran au-dessus.

    Deux facons de le fermer, si le terrain l'exige : chainer les campagnes entre elles —
    la premiere enveloppe d'une campagne portant l'empreinte de la derniere de la
    precedente, ce que `DeviceRecord.last_envelope_digest` sait deja faire sans rien
    changer au format — ou tenir la liste des campagnes au niveau du dossier, hors
    enveloppe, ce qui deplace la confiance vers le serveur metier.

    **La premiere est presque gratuite et se contente de ne pas reinitialiser un champ.**
    Elle n'est pas retenue ici parce qu'elle a un cout reel : elle rend une visite
    indivisible, donc impossible a remettre par morceaux, et fait dependre chaque campagne
    de la bonne reception de la precedente. Cela se tranche quand on saura si le dossier
    opposable est la visite ou la campagne — question de produit, pas de format.

## Consequences

- **Le CDDL et la specification §2 changent** : `freshness` passe optionnel, avec la
  condition d'admissibilite du point 2 ecrite en toutes lettres. Les deux fichiers se
  tiennent synchrones a la main ; c'est exactement le genre de modification ou l'ecart se
  cree.

- **Le verificateur gagne un chemin, pas une exception.** Enveloppe sans `freshness` :
  exiger `payload[7]`, verifier la chaine, noter `integrity` au grade de maillon, et
  produire un motif. Un `CHAIN_BROKEN` sur une enveloppe sans fraicheur est un rejet, non
  un drapeau : il ne reste alors plus rien qui atteste quoi que ce soit.

- **Le coeur gagne une API de serie** — ouvrir, ajouter, clore — et elle vit naturellement
  a cote de la session de capture d'ADR-0008, qui possede deja la camera pour la duree
  d'une seance. Les deux decisions se composent sans se recouvrir : l'une dit qui possede
  le capteur, l'autre ce que plusieurs prises signifient ensemble.

- **`DeviceRecord.last_envelope_digest` suffit** au chainage lineaire. Une serie qu'on
  voudrait pouvoir verifier hors ordre d'arrivee demanderait davantage ; ce n'est pas
  tranche ici, et ne doit pas l'etre par accident.

- **La ligne « Chainage Android » de la specification §9 se ferme.** L'autre option
  qu'elle proposait — un compteur monotone dans le Keystore — n'est pas retenue : elle
  n'aurait rien dit de l'absence de retrait, seulement de l'ordre.

- **Le plafond de `time` sur Android tombe** pour les series : `envelope-chain-verified`
  existe deja et fait passer `time` en A. C'est le seul frein qui restait apres A4.2.

## Ce qui ferait revenir sur cette decision

Si une mesure montrait que la fraicheur par enveloppe tient a la cadence reelle d'un
constat de terrain — quelques prises espacees de dizaines de secondes plutot qu'une
rafale —, la serie perdrait son argument le plus concret cote Android. Elle garderait
l'autre, l'absence de retrait, qui suffit ; mais le point 2 deviendrait un desserrage
gratuit, et il faudrait alors exiger la fraicheur partout.

Si l'attestation de cle par capture devenait abordable (spec §9, « verification Android
hors ligne »), un maillon pourrait porter une preuve d'integrite **vivante** sans appeler
Google. Le point 5 perdrait sa raison d'etre, et le grade de maillon rejoindrait celui
d'une tete. C'est le seul chemin connu pour lever ce plafond.

Si un besoin apparaissait de verifier une serie **hors ordre d'arrivee** — reseau
intermittent, envois desordonnes —, le chainage lineaire ne suffirait plus. La reponse
serait un arbre de hachage, pas un identifiant de session : la propriete recherchee reste
l'absence de retrait, et elle ne se declare pas.
