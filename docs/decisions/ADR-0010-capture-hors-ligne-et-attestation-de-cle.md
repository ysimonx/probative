# ADR-0010 — Capture hors ligne : l'attestation de cle comme troisieme preuve de fraicheur

**Statut :** accepte
**Date :** 2026-08

## Contexte

**La capture hors ligne devient une exigence produit**, enoncee le 2026-08-17. Le format
ne la sert aujourd'hui qu'a moitie, et l'asymetrie entre les deux plateformes est totale.

**iOS sait deja attester hors ligne.** Une assertion App Attest se fabrique
**localement**, sans appeler Apple. Seul le nonce doit avoir ete pre-delivre.

**Android ne le peut pas** avec Play Integrity : le jeton vient des serveurs de Google.
Sans reseau, aucun jeton -- ni pour une tete de serie, ni pour une prise isolee. Une
enveloppe Android hors ligne ne peut donc porter *aucune* preuve de fraicheur au sens
actuel du format.

**Mais Android dispose d'un autre chemin, deja nomme dans la specification.** La §9
laissait ouverte la « verification Android hors ligne » avec cette option : faire voyager
une **attestation de cle par capture** dans l'enveloppe. Elle y posait une condition
d'arbitrage explicite -- *a trancher avec A4, quand la latence de capture sera mesuree* --
en detaillant deux couts sur SM-X200 : **3 413 octets** de chaine pour une enveloppe d'or
de 629, et **38 ms a chaud, 264 ms a froid** de generation de cle, qui atterriraient dans
`media[6]`.

**A4.2 est faite, la latence est mesuree** : `media[6]` vaut 60 a 157 ms en profil
`capture` sur ce meme appareil, contre un seuil a 3 000. La condition posee par la
specification est donc levee, et l'argument du cout en latence s'est affaibli comme elle
l'anticipait.

Un troisieme fait, mesure le meme jour, fermait la voie concurrente : le bridage de Play
Integrity venait des `prepare` repetes et non des demandes de jeton. La fraicheur par
enveloppe tient donc a la cadence reelle **en ligne** -- ce qui, par la clause de reouverture
d'ADR-0009, retire au desserrage de `freshness` sa justification. Il n'en reste qu'une, et
c'est celle-ci : le hors ligne.

## Decision

1. **`key-attestation` devient un troisieme type de preuve de fraicheur.** Le CDDL passe
   a `1 => "play-integrity" / "app-attest" / "key-attestation"`. **`freshness` reste
   obligatoire** : aucune enveloppe ne circule sans preuve de fraicheur, et le desserrage
   qu'envisageait ADR-0009 point 2 est abandonne au profit de celui-ci.

2. **`freshness[2]` reste opaque et son interpretation depend du type**, comme
   aujourd'hui -- un jeton Play Integrity est une chaine JWT, une assertion App Attest est
   du CBOR. Pour `key-attestation`, c'est un `bstr` **contenant** un tableau CBOR de
   certificats DER, de la feuille a la racine. Aucun autre changement de CDDL que
   l'enumeration.

   *Precision du 2026-08-17, la premiere redaction etant ambigue.* Un tableau CBOR **nu**
   en `freshness[2]` serait refuse : `model.py` le decode par `_as_blob`, qui n'accepte que
   des octets. Un `bstr` portant du CBOR encode ne demande donc **aucun** changement du
   decodeur, la ou un tableau nu en aurait exige un et aurait elargi le CDDL. La forme
   choisie est la moins couteuse des deux, et elle etait deja celle des deux autres types.

3. **R1 est inchangee, et c'est tout l'interet.** Le defi soumis a
   `setAttestationChallenge` vaut exactement `SHA-256(payload_bytes ‖ nonce)` -- le meme
   condensat que `requestHash` cote Play Integrity et que `clientDataHash` cote App
   Attest. Le TEE l'inscrit dans le certificat feuille, ou le serveur le recalcule et le
   confronte. **Ceci n'est pas un assouplissement de l'invariant 2 : c'est une autre
   source de la meme preuve.**

4. **La cle attestee par capture est distincte de la cle de signature enrolee.** La
   seconde garde son `kid` stable -- sans quoi le serveur ne reconnaitrait plus l'appareil
   et le chainage tomberait, comme constate le 2026-08-17. La cle attestee est engendree
   pour la capture, porte le defi, et est detruite ensuite.

5. **Le `RootOfTrust` d'une enveloppe hors ligne est frais, et c'est un gain.** Lu dans
   l'attestation de la cle engendree a la capture, `deviceLocked` et `verifiedBootState`
   valent **a l'instant de la prise**, la ou `boot-verified-at-enrollment` ne vaut qu'a
   l'enrolement -- avec sa faille connue : s'enroler verrouille, puis deverrouiller.

6. **Une enveloppe hors ligne ne peut pas revendiquer le verdict d'appareil de Google.**
   `integrity` est donc note sur ce qui est reellement etabli -- cle materielle, ancrage
   a la racine constructeur, `RootOfTrust` frais -- et **sous** le grade d'une enveloppe
   portant un verdict de fournisseur en ligne. Le motif le dit.

7. **Le plafond `DEGRADED` sur nonce pre-delivre est leve, et remplace par la largeur
   observee.** `overall_level` ramene aujourd'hui tout hors ligne a `DEGRADED`, quel que
   soit le reste. C'est un **mode**, et `max_nonce_window_ms` mesure deja la grandeur qui
   compte : la distance entre l'emission du nonce et le jugement. Un nonce pre-delivre
   consomme dans la minute n'a pas a etre traite comme un nonce vieux de trois jours.
   **Invariant 8.**

8. **Trois mesures conditionnent l'implementation**, dans cet ordre : le cout reel en
   octets sur une enveloppe `capture` complete ; ~~la latence de generation de cle **apres
   l'obturateur**, donc dans `media[6]`, sur appareil froid~~ **le cout en temps mural du
   scellement** (voir la correction ci-dessous) ; et la verification que
   `attestationApplicationId` identifie bien l'application de maniere exploitable.

   **Correction du 2026-08-17 : la generation de cle ne peut pas entrer dans `media[6]`,
   et la redaction d'origine se trompait de champ.** Dans `Sealer.kt`, `latencyMs` -- la
   valeur de `media[6]` -- est fige **avant** la construction de la charge utile, tandis
   que `freshness.token(challenge)` est appele dans `finir()`, apres l'encodage. Le
   commentaire du fichier le disait deja : « le champ est *dans* ce qui est encode, donc il
   ne peut pas mesurer ce qui vient apres lui ».

   **Et l'ordre est impose par R1 elle-meme.** Le defi vaut `SHA-256(payload_bytes ‖
   nonce)` : il n'existe pas avant l'encodage de la charge utile. Il n'y a donc aucun
   arbitrage a rendre -- la cle **ne peut etre engendree qu'apres**, faute de defi a lui
   soumettre.

   Ce qui reste a mesurer est donc le **temps mural du scellement**, qui pese sur la
   latence ressentie par l'utilisateur et sur rien d'autre. C'est une question de confort,
   pas de verdict, et elle ne peut pas invalider cette decision.

   **La troisieme est faite, le 2026-08-17, et elle est concluante.** Decodee sur le
   vecteur `keystore-a3-sm-x200.json` deja versionne, sans appareil : le tag 709 de
   `softwareEnforced` porte le nom de paquet, sa version, et l'empreinte de signature.
   Celle-ci vaut `63:14:CF:92:…`, **exactement** ce qu'un calcul independant depuis
   `~/.android/debug.keystore` avait donne le meme jour -- deux chemins qui se recoupent.

   Deux consequences, et la seconde n'etait pas prevue :

   - **le champ vit dans `softwareEnforced`**, donc affirme par le systeme et non par le
     TEE. Il ne vaut que ce que vaut le demarrage verifie -- ce que `RootOfTrust`, lui
     **hardware-enforced**, etablit precisement. La dependance est propre : une assertion
     logicielle adossee a une preuve materielle de l'integrite du systeme qui l'emet ;
   - **hors ligne et sur Android, `origin` ne peut pas atteindre `app-recognized`.** Ce
     verdict signifie « ce binaire est celui que Play distribue », et aucune attestation
     locale ne peut le dire. Ce que le champ 709 etablit -- ce paquet, signe par cette
     cle -- correspond exactement au cas que `GradingPolicy.deployment_signed_app_grade`
     note deja, **C par defaut**. Une capture Android hors ligne sortira donc en
     `DEGRADED` a politique inchangee, et c'est coherent : elle prouve moins.

9. **Le hors ligne est asymetrique entre les plateformes, et il faut le dire.** Une
   premiere redaction de cet ADR generalisait la conclusion ci-dessus a « une capture hors
   ligne » ; c'est faux pour iOS.

   | | iOS hors ligne | Android hors ligne |
   |---|---|---|
   | identite de l'application | **`app-recognized`** | `deployment-signed` -> C |
   | integrite | `STRONG`, verifiee hors ligne | `RootOfTrust` frais, sans verdict Google |
   | ordonnancement | compteur d'assertion -> A | chainage -> A |
   | **niveau atteignable** | **`STANDARD`**, voire `STRONG` en `core` | **`DEGRADED`** |

   App Attest lie son assertion a `teamID.bundleID` par le `rpIdHash`, et ce controle ne
   demande aucun reseau : `app_attest.py` pose donc `app_recognized=True` hors ligne comme
   en ligne. Rien chez Google n'a d'equivalent -- « ce binaire est celui du magasin » n'est
   etablissable que par un appel a Play.

   **L'invariant 4 pose que les deux plateformes atteignent le meme niveau par des chemins
   differents. Hors ligne, elles ne l'atteignent pas.** Ce n'est pas un defaut du format --
   aucun champ obligatoire propre a une plateforme n'est introduit -- mais c'est un ecart
   de capacite, structurel, et le taire ferait promettre au produit ce qu'il ne tient pas
   sur la moitie du parc.

   **Largement referme par ADR-0011 le meme jour.** Le hors ligne n'est pas un etat
   permanent : le produit comporte un moment de **validation**, ou le reseau revient. Un
   jeton Play Integrity demande a ce moment-la, avec `requestHash` valant le R1 d'une
   enveloppe deja scellee, rend a Android son `app-recognized`. L'ecart ci-dessus ne
   subsiste donc que pour une campagne **jamais validee**.

## Justification

- **Le point 1 renverse la solution d'ADR-0009 point 2, et c'est un progres.** Rendre
  `freshness` optionnel revenait a admettre des enveloppes sans preuve de fraicheur, avec
  un chemin de verification supplementaire et une notation degradee. Ici, l'enveloppe
  porte une preuve **complete et liee**, simplement d'une autre origine. Le format se
  resserre au lieu de se desserrer.

- **Le point 3 est ce qui rend cette voie acceptable la ou l'autre ne l'etait qu'a
  regret.** Le mecanisme d'attestation de cle est *concu* pour recevoir un defi : c'est
  litteralement la meme figure que R1, et le depot l'a deja exercee -- le vecteur
  d'appareil `keystore-a3-sm-x200.json` porte un defi qui vaut `SHA-256(payload ‖ nonce)`,
  verifie par recalcul.

- **Le point 5 repare une faiblesse que le hors ligne aurait du aggraver.** C'est
  contre-intuitif et merite d'etre souligne : une enveloppe hors ligne est, sur ce point
  precis, **mieux** etayee qu'une enveloppe en ligne, dont le `RootOfTrust` date de
  l'enrolement.

- **Un gain d'opposabilite, qui n'etait pas recherche.** Un jeton Play Integrity ne se
  revverifie pas des annees plus tard : Google ne le dechiffre plus passe un court delai.
  Une chaine de certificats, elle, se verifie hors ligne et indefiniment. Pour une piece
  destinee a etre opposee longtemps apres, l'ecart est majeur -- et il rapproche cette
  voie de ce que la §9 attend d'un horodatage RFC 3161.

- **La faiblesse residuelle est le relais, et elle doit etre nommee.** L'attestation
  prouve qu'*une* cle a ete engendree dans un composant securise avec ce defi ; elle ne
  prouve pas que ce composant est celui qui detient la cle de signature enrolee. Un
  attaquant possedant la cle enrolee d'un appareil compromis pourrait faire produire
  l'attestation par un second appareil sain. Play Integrity n'a pas cette faille, le jeton
  etant lie a l'appareil par Google. C'est une raison de plus pour le point 6 : hors ligne
  note **sous** en ligne, et le motif doit le dire.

- **Le point 7 applique l'invariant 8 a un cas qui l'attendait.** « Hors ligne » est un
  mode ; « largeur d'encadrement du nonce » est une grandeur mesuree, et le verificateur
  la connait deja. C'est la troisieme occurrence du meme travers, apres `offline: bool`
  dans `grade_time` et « serie close ou non » dans ADR-0009 -- ce qui confirme que
  l'invariant meritait d'etre ecrit.

- **Le point 8 refuse de decider par assertion ce qui se mesure.** Le cout en octets est
  connu sur une enveloppe d'or de 629 octets, pas sur une enveloppe `capture` reelle de
  1 700. Et la latence de 264 ms a froid n'a jamais ete mesuree *apres l'obturateur* :
  c'est la seule position ou elle compte.

## Consequences

- **Le CDDL et la specification §2 changent d'une ligne** : l'enumeration de
  `freshness[1]`. C'est le seul changement de format, et il est additif -- une enveloppe
  v0.1 existante reste valide.

- **La specification §9 perd sa ligne « verification Android hors ligne »**, tranchee ici,
  et voit son plafond `DEGRADED` sur lot de nonces remplace par la notation en largeur.
  Cette derniere etait explicitement signalee comme « un desserrage, donc par ADR » : le
  present ADR en tient lieu.

- **ADR-0009 point 2 est abandonne.** `freshness` reste obligatoire. Ce qui subsiste de
  cet ADR est le chainage -- deja implemente et valide -- et l'interdiction d'un
  identifiant de session declare.

- **L'aiguillage du verificateur devra changer, et l'ADR ne l'avait pas vu.** Le choix du
  `AttestationVerifier` se fait aujourd'hui sur `claims.posture.platform` seul
  (`verifier.py`, `PerPlatformVerifier` dans `devserver.py`) ; `Freshness.kind` est decode
  mais **jamais lu** dans `src/`. Or une enveloppe Android portera desormais **soit** Play
  Integrity **soit** `key-attestation`, selon qu'elle a ete produite en ligne ou non.
  L'aiguillage doit donc devenir fonction du couple plateforme + type. Constat du
  2026-08-17, a traiter a l'implementation.

- **Le verificateur gagne un troisieme `AttestationVerifier`**, qui n'appelle personne :
  `verify_key_attestation` existe deja et fait l'essentiel -- ancrage aux racines Google,
  recalcul du defi, lecture du `RootOfTrust`. Il faut l'habiller en `AttestationOutcome`
  et decider ce que valent ses champs, notamment `app_recognized`, que
  `attestationApplicationId` pourrait renseigner sous reserve du point 8.

- **Le coeur Android gagne un mode d'acquisition hors ligne** : engendrer une cle avec le
  defi, joindre sa chaine, detruire la cle. La cle de signature enrolee ne bouge pas.

- **iOS n'a rien a changer.** App Attest fonctionne deja hors ligne ; la seule contrainte
  restante y est le nonce pre-delivre, que le point 7 cesse de punir forfaitairement.
  L'invariant 4 est respecte : le format decrit trois sources de fraicheur, aucune
  obligatoire, aucune propre a une plateforme.

## Ce qui ferait revenir sur cette decision

Si les mesures du point 8 montraient que la chaine fait franchir a l'enveloppe un seuil de
transport inacceptable pour le terrain vise -- une enveloppe de 5 Ko la ou le lien ne
passe qu'un kilo-octet --, la voie resterait valable mais deviendrait un profil de
deploiement plutot qu'un mode general.

~~Si la latence de generation de cle apres l'obturateur s'averait du meme ordre que le
seuil `max_sign_latency_ms`, il faudrait engendrer la cle **avant** l'obturateur, ce qui
detacherait l'attestation de la charge utile et ferait perdre R1.~~ **Clause retiree le
2026-08-17 : le scenario est impossible, pas seulement indesirable.** Le defi d'attestation
*est* R1, et R1 n'existe qu'une fois la charge utile encodee -- donc une fois `media[6]`
deja fige. Engendrer la cle « avant » n'aurait aucun defi a recevoir. Cette voie n'a jamais
pu etre tuee par cette mesure, et la croire menacee a coute une inquietude inutile.

Si Apple ou Google fermait l'attestation de cle hors ligne -- provisionnement distant
exigeant un aller-retour --, le hors ligne Android redeviendrait sans solution, et il
faudrait alors trancher ce qu'une enveloppe sans aucune preuve de fraicheur peut valoir,
question que cet ADR a precisement rendue inutile.
