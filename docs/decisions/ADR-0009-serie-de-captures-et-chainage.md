# ADR-0009 — Serie de captures : tete attestee, maillons chaines, queue attestee

**Statut :** accepte
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

1. **Une serie est une tete attestee, des maillons chaines, et une queue attestee.** La
   tete et la queue portent une preuve de fraicheur complete, liee a leur propre charge
   utile par R1. Les maillons intermediaires portent `payload[7]` et rien d'autre.

2. **`freshness` devient optionnel** — `? 200 => freshness` au CDDL. Son absence n'est
   admissible **que** si `payload[7]` est present et si la chaine se verifie ; sinon,
   rejet. Jamais de repli silencieux.

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

6. **`time` sur un maillon garde le benefice du chainage.** `envelope-chain-verified`
   promeut deja `time` en A, et c'est correct : l'ordre est exactement ce que la chaine
   etablit.

7. **Une serie sans queue attestee est signalee.** Elle reste ouverte par le bas : rien
   ne borne la fenetre pendant laquelle l'appareil a pu etre compromis apres la tete.

## Justification

- **Le point 1 est l'encadrement bilateral, applique a une serie.** C'est la meme figure
  que le nonce donne deja au temps : la charge utile le contient donc la capture lui est
  posterieure, le serveur l'a recue avant expiration donc elle lui est anterieure. Deux
  points attestes et une chaine entre eux bornent la serie des deux cotes — rien ne peut
  y etre insere, retire, ni reordonne, et R2 continue de prouver **quel appareil** a
  chaque maillon.

- **Le point 5 est ce qui rend le point 2 acceptable plutot que complaisant.** Un
  attaquant qui obtient une tete attestee puis compromet l'appareil peut produire des
  maillons suivants : la chaine ne s'en apercevra pas. C'est la faiblesse exacte de cette
  decision, et elle est payee par le grade, pas dissimulee. Le point 7 la borne.

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
