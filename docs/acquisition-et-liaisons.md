# Acquisition et liaisons — discussion ouverte

**Ouvert le 2026-08-15. Rien n'est décidé ici.** Ce document existe pour qu'une
discussion tenue à l'oral survive au poste et se reprenne ailleurs. Il porte des
constats, des pièges identifiés et **deux décisions à prendre** — la propriété de la
session de capture (§ 2), et le niveau que doit viser une série hors ligne (§ 4) ; il ne
fait autorité sur rien. Le jour où l'un de ces sujets se tranche, cela devient un ADR et
cette section disparaît d'ici.

La première décision commande : l'aperçu et la série de captures sont le **même**
remaniement, et le trancher deux fois donnerait deux réponses.

## Pourquoi maintenant

Le chemin d'acquisition va bientôt recevoir deux choses qu'il n'a pas : une **surface
d'interface** (prévisualisation, zoom, mise au point) et un **pont** vers un framework
(Flutter d'abord, React Native ensuite — ADR-0003). Les deux arrivent ensemble, parce que
c'est le même besoin qui les amène : un intégrateur veut son écran de prise de vue.

Aucun des deux n'est commencé. Ce qui suit est ce qu'on sait déjà, et qu'il serait coûteux
de redécouvrir.

---

## 1. La couture avec la liaison

**Ce qui est acquis** (ADR-0003) : tout le chemin critique reste natif, le pont ne reçoit
que l'enveloppe signée, opaque.

Concrètement, `Camera.capture()` et `Sealer.seal(image:)` vivent tous deux dans le cœur :
`CapturedImage` n'a **aucune raison de traverser le pont**. La liaison expose un appel —
*scelle une acquisition sous ce nonce* — et reçoit l'enveloppe plus les octets.

> **Le test de la couture.** Si l'API du plugin, pour le chemin `capture`, fait plus d'un
> appel, quelque chose a fui du cœur vers le framework.

**Le contre-modèle est `camera.dart`**, le greffon Flutter courant. Il fait traverser les
trames vers Dart et rend un widget de prévisualisation côté framework. Copier cette forme
détruirait le profil `capture` : `media[6]` avalerait le coût du pont, et le contenu
deviendrait modifiable dans la couche la moins fiable de la pile — or `media[6]` est le
discriminant d'injection, et le chemin court est tout ce que `capture` apporte de plus que
le noyau (spec §2.5).

**Les octets finissent tout de même par atteindre Dart**, puisqu'il faut les stocker ou les
envoyer. Une seule traversée, après scellement, par chemin de fichier plutôt que par copie
— 2,3 Mo mesurés sur iPhone 16. Et la liaison doit **répéter l'interdiction de les
ré-encoder** (spec §2.3, normative depuis ADR-0007) : c'est exactement le genre de règle
qu'une couche d'abstraction fait oublier.

---

## 2. La prévisualisation — **décidée, ADR-0008**

> **Tranchée le 2026-08-17 : le cœur possède la session, la vue s'y rattache en
> consommateur.** Voir `decisions/ADR-0008-propriete-de-la-session-de-capture.md`, qui
> porte la décision, ses six points et ce qui la ferait rouvrir. La section ci-dessous
> reste telle qu'elle a servi à instruire le choix — elle en garde le raisonnement, y
> compris le piège de la trame d'aperçu, devenu normatif.
>
> Deux arguments ont emporté la décision, et le second n'apparaît pas ci-dessous : une
> session possédée par la vue ferait signer au cœur des octets dont il n'a pas vu la
> naissance, ce qui vide le profil `capture` de son sens ; et elle mettrait une part du
> chemin critique dans la liaison, ce qu'ADR-0003 interdit.

Le cœur n'en a pas, délibérément : la session vit le temps d'une photo
(`startRunning()`, capture, `defer { stopRunning() }`).

**La partie graphique est de la plomberie connue** et ne mérite pas d'inquiétude :
`AVCaptureVideoPreviewLayer` s'attache à la session existante comme simple consommateur ;
côté Android c'est le cas d'usage `Preview` de CameraX lié à côté d'`ImageCapture` ; côté
Flutter, une vue de plateforme (`UiKitView` / `AndroidView`).

**Le coût réel est le cycle de vie.** Un aperçu fait vivre la session des minutes, et la
capture se produit *pendant*. Ce n'est pas un ajout à `Camera`, c'est un changement de
forme. D'où la seule question qui compte :

> **Qui possède la session de capture — la vue de plateforme, ou le cœur ?**

Si c'est la vue, `capture()` doit l'emprunter. Si c'est le cœur, la vue doit s'y rattacher.
Se tromper produit deux sessions qui se disputent la caméra — le mode de défaillance
prévisible de toute intégration naïve, et la raison pour laquelle un intégrateur serait
tenté d'utiliser `camera.dart` pour l'aperçu et le cœur pour la capture. **À trancher avant
d'écrire quoi que ce soit**, y compris avant la liaison Flutter.

**Un effet de bord favorable, à ne pas rater — mais pas là où on le croit.** Avec un aperçu
vivant, la session est déjà sous tension et convergée au déclenchement. Ce que cela supprime
est **la latence perçue par l'utilisateur** : mise sous tension du capteur, délai de garde de
400 ms, et attente 3A avant l'obturateur. C'est le gros du temps mural, et c'est déjà une
raison suffisante.

> ~~`media[6]` devrait s'améliorer parce que les 400 ms de convergence sont aujourd'hui
> *dans* `capture()`.~~ **Le raisonnement est faux, corrigé le 2026-08-15.** Elles y sont,
> mais `media[6]` part de l'obturateur (`willCapturePhotoFor`) : ni elles, ni la mise sous
> tension, ni l'attente 3A n'y ont jamais figuré — les trois sont en amont. Ce que le champ
> noté mesure après l'obturateur, c'est l'encodage puis le scellement, et **rien n'établit
> qu'un aperçu les raccourcisse**. Ne pas justifier l'aperçu par `media[6]` : il se justifie
> par la latence perçue, qui suffit. `CaptureTimings` dira terme à terme s'il y a un gain
> résiduel.

> **Le piège à écrire avant que quelqu'un ne l'essaie.** Ne jamais produire les octets
> scellés en attrapant la trame d'aperçu courante. C'est tentant — obturateur instantané,
> coût nul — mais cela les fait sortir du pipeline **vidéo** au lieu du pipeline photo :
> autre traitement, autre qualité, et une provenance qui n'est plus celle qu'on documente.
> Le cœur doit rester sur `AVCapturePhotoOutput`.

**Une échappatoire existe déjà** et limite la pression : un intégrateur qui veut maîtriser
tout son écran passe par `seal(content:)` et obtient le profil `core`. L'aperçu n'est
nécessaire que pour `capture`.

---

## 3. Les commandes de prise de vue

**L'exécution doit être native**, sans alternative : zoom, mise au point, exposition et
torche agissent sur l'`AVCaptureDevice` de la session que le cœur possède. Les piloter
depuis Dart imposerait une seconde session.

**Mais `Camera.swift` ne doit pas devenir un tableau de bord.** La forme préférable est un
type valeur passé à `capture(format:settings:)`, plutôt qu'une pile de méthodes mutantes —
ce qui préserve le test de la couture ci-dessus. Avec un aperçu, ces réglages deviennent
forcément interactifs et migrent sur la poignée de session : c'est encore la question de
propriété du § 2.

**Mise au point, exposition, torche : sans enjeu.** Elles changent ce qu'il y a dans le
cadre, pas d'où il vient.

**Deux commandes ne sont pas neutres, et c'est le vrai sujet de cette section.**

### Zoom numérique — il dégrade les octets scellés, en silence

C'est un recadrage suivi d'un rééchantillonnage : exactement le « redimensionnement » que
la spec §2.3 nomme comme destructeur. Il a lieu **dans** le pipeline, avant les octets
qu'on hache — il ne viole donc pas l'interdiction de ré-encoder, mais les octets cessent
d'être une lecture directe du capteur, et le vérificateur n'en sait rien.

Deux issues acceptables, et une seule inacceptable :

- porter le facteur effectif dans un `claim` (§2.4) — extensible et non cassant par
  construction, un type inconnu étant ignoré silencieusement ;
- l'assumer comme angle mort **nommé**, à la manière de la recapture analogique ;
- ne rien écrire. C'est la seule issue à exclure.

### Zoom optique — c'est un autre capteur physique

Passer au téléobjectif change de capteur. Aujourd'hui le cœur épingle
`builtInWideAngleCamera` arrière : le capteur est **déterministe**, et c'est une propriété
qu'on perdrait sans s'en apercevoir.

Conséquence directe sur la piste PRNU (inconnue n° 5) : une empreinte enrôlée sur un
objectif ne vaut rien pour un autre. Si cette piste doit rester ouverte, l'identité de
l'objectif devra être enrôlée et inscrite dans l'enveloppe.

---

## 4. La série de captures — une session, plusieurs prises

**La proposition, telle que posée le 2026-08-15 :** démarrer la session une fois, enchaîner
plusieurs prises, la couper à la fin. La forme naturelle d'un relevé de terrain, où
l'opérateur prend dix photos d'affilée et non une.

**Ce n'est pas un gain sur `media[6]`, et il faut le dire d'emblée.** Les quatre bornes
qu'une session persistante mutualise — configuration, mise sous tension, garde de 400 ms,
convergence 3A — sont **toutes en amont de l'obturateur**. Elles ne sont pas dans le champ
noté et ne l'ont jamais été. Le gain est du temps mural : réel, considérable pour les prises
2 à N, et sans effet sur le verdict. C'est exactement l'erreur corrigée au § 2, et elle se
réintroduirait volontiers par cette porte.

**Le blocage n'est pas la caméra, c'est le nonce.** Un nonce vaut pour une enveloppe : émis
par le serveur, à usage unique, refusé définitivement une fois consommé (spec § R3), 120 s
de durée de vie par défaut dans le serveur de développement. N prises, N nonces. Deux voies,
et une seule est bonne :

- **un lot pré-délivré** — c'est le mode hors ligne, que la spec **plafonne à `DEGRADED`**
  (même section). Le lot est précisément le gisement que R3 ferme ;
- **un nonce d'avance**, obtenu pendant que l'opérateur cadre la prise suivante. Préserve
  `nonce-fresh`, ne coûte rien au temps perçu, exige de la connectivité tout du long.

> **La tension à ne pas escamoter.** Le cas d'usage qui motive la série est celui où le
> réseau manque. Le format a déjà tranché ce compromis — hors ligne, c'est `DEGRADED` — donc
> la question ouverte n'est pas technique mais d'exigence : *une série de terrain doit-elle
> viser `STANDARD` avec réseau, ou accepter `DEGRADED` sans ?* Y répondre par un lot de
> nonces sans le dire reviendrait à desserrer R3 en silence.

### Le lot de session, et pourquoi il n'est pas le lot de la spec

L'objection immédiate — *demander un lot au début de la série* — mérite mieux qu'un renvoi à
R3, parce qu'elle vise autre chose que ce que R3 avait en tête. La spec écrit « durée de vie
étendue » en pensant au hors-ligne au long cours ; **un lot de session est borné par la
session** : quarante-cinq minutes de validité pour trente minutes de relevé.

Ce que le nonce achète est un encadrement bilatéral, et **sa largeur est exactement la durée
de vie du nonce**. Un lot ne dégrade donc pas `time` par sa cardinalité mais par sa
longévité — ce que le plafond actuel ne distingue pas, puisqu'il porte sur un drapeau et non
sur une largeur. La question est ouverte en spec § 9 ; elle n'appartient pas à ce document,
qui n'a qu'à en connaître la conclusion.

**La forme à privilégier ne demande aucun changement de spec : un nonce d'avance.**
Le récupérer pendant que l'opérateur cadre la prise suivante. Il ne faut alors pas du réseau
*à l'obturateur*, seulement dans les secondes autour — ce qui couvre le réseau intermittent,
c'est-à-dire l'essentiel des situations de terrain. Encadrement serré conservé, `STANDARD`
accessible, et le lot reste disponible comme repli hors ligne assumé.

**Le vrai gain est ailleurs : le chaînage.** `previousDigest` existe déjà sur les deux
points d'entrée de `Sealer`, et le champ 7 est dans le format. Aujourd'hui il ne sert à
rien — une prise isolée n'a rien à chaîner. Une série lui donne son sens : elle établit
l'ordre des prises et le fait qu'aucune n'a été retirée. Et l'asymétrie compte, à l'étape 7
de l'ordre de vérification : le chaînage est **noté côté Android**, là où iOS obtient `time`
au grade A par le compteur d'assertion signé. C'est donc un gain de grade concret sur la
plateforme qui en a besoin — et la série est le cas d'usage qui instruirait enfin
l'inconnue n° 3.

**Multi-captures et aperçu sont le même remaniement.** Une session qui survit à un appel
cesse d'être une fonction pour devenir un objet à durée de vie. C'est mot pour mot le
changement de forme qu'appelle l'aperçu, et donc la même question de propriété qu'au § 2.
**Ne pas ouvrir ce chantier avant de l'avoir tranchée** : on la trancherait deux fois, et
probablement pas dans le même sens.

**Trois points à ne pas perdre.** Une session longue se fait interrompre — appel entrant,
passage en arrière-plan, autre application qui prend la caméra ; aujourd'hui elle vit deux
secondes et le cas ne se pose pas. Il faudra le traiter, et surtout garantir qu'une session
morte ne produise jamais une enveloppe d'apparence valide. Chaque prise consomme sa propre
preuve de fraîcheur : 18 ms d'assertion sur iPhone 16, donc négligeable, mais côté Android
c'est une requête Play Integrity par enveloppe et **les quotas sont à vérifier avant de
promettre une cadence**. Enfin l'échauffement, sur une session qui dure des minutes.

> **Invariant 3, et ce n'est pas une formalité.** Le mot qui a amené cette discussion
> — « inspection » — est du vocabulaire métier et n'entre pas dans ce dépôt. Le concept s'y
> nomme **série de captures**. C'est typiquement par une fonctionnalité motivée par un
> terrain précis qu'un domaine applicatif s'installe dans une API.

---

## Ce qui est acquis, ce qui est ouvert

| Sujet | État |
|---|---|
| Le pont ne reçoit que l'enveloppe signée | **Acquis** — ADR-0003 |
| Un seul appel pour le chemin `capture` | Proposé, non écrit |
| Les octets traversent une fois, après scellement, par chemin de fichier | Proposé, non écrit |
| Propriété de la session avec aperçu | **Ouvert — à trancher en premier** |
| Ne jamais sceller une trame d'aperçu | Constat, à rendre normatif |
| Réglages en type valeur plutôt qu'en méthodes mutantes | Proposé, non écrit |
| Traitement du zoom numérique | **Ouvert** — `claim`, ou angle mort nommé |
| Identité de l'objectif si le zoom optique s'ouvre | Ouvert, lié à l'inconnue n° 5 |
| Série de captures : même remaniement que l'aperçu | Constat, dépend de la même décision |
| Un nonce d'avance plutôt qu'un lot | Proposé — sans changement de spec |
| Lot de session noté à la largeur, non au drapeau | **Ouvert en spec § 9** — desserrage, donc ADR |
| Niveau visé par une série hors ligne | **Ouvert** — exigence, pas technique |
| Le chaînage prend son sens dans une série | Constat, instruirait l'inconnue n° 3 |

## Renvois

- `docs/decisions/ADR-0003-coeurs-natifs-liaisons-minces.md` — la stratégie de liaison
- `docs/decisions/ADR-0007-format-acquisition-octets-immuables.md` — format et conservation
- `docs/envelope-spec.md` §2.3 (conservation des octets), §2.4 (`claim`), §2.5 (profils, et
  ce que l'acquisition par le cœur apporte ou non), R3 (unicité du nonce, lot hors ligne),
  §9 (chaînage)
- `CLAUDE.md`, inconnues n° 2 (latence), n° 3 (chaînage Android) et n° 5 (PRNU)
- `CaptureTimings` dans `mobile/ios/Sources/ProbativeCore/Camera.swift` — la décomposition
  qui rend les affirmations de latence de ce document vérifiables plutôt que plausibles
