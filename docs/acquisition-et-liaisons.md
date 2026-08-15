# Acquisition et liaisons — discussion ouverte

**Ouvert le 2026-08-15. Rien n'est décidé ici.** Ce document existe pour qu'une
discussion tenue à l'oral survive au poste et se reprenne ailleurs. Il porte des
constats, des pièges identifiés et **une décision à prendre** ; il ne fait autorité sur
rien. Le jour où l'un de ces sujets se tranche, cela devient un ADR et cette section
disparaît d'ici.

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

## 2. La prévisualisation — la décision à prendre

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

**Un effet de bord favorable, à ne pas rater.** Les 400 ms de convergence de session sont
aujourd'hui *dans* `capture()`. Avec un aperçu vivant, la session est déjà convergée au
déclenchement : `media[6]` devrait s'améliorer. Vu la marge mesurée (inconnue n° 2), ce
n'est pas anecdotique.

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

## Renvois

- `docs/decisions/ADR-0003-coeurs-natifs-liaisons-minces.md` — la stratégie de liaison
- `docs/decisions/ADR-0007-format-acquisition-octets-immuables.md` — format et conservation
- `docs/envelope-spec.md` §2.3 (conservation des octets), §2.4 (`claim`), §2.5 (profils, et
  ce que l'acquisition par le cœur apporte ou non)
- `CLAUDE.md`, inconnues n° 2 (latence) et n° 5 (PRNU)
