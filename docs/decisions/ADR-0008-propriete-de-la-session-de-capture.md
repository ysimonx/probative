# ADR-0008 — Le coeur possede la session de capture

**Statut :** accepte
**Date :** 2026-08

## Contexte

Le coeur n'a pas d'apercu, deliberement : la session vit le temps d'une photo —
`startRunning()`, capture, `stopRunning()` en sortie de portee. C'est ce que fait
`Camera.swift` depuis C4.2, et c'est suffisant tant qu'aucun ecran n'affiche ce que
l'objectif voit.

Un apercu change cela, et **la partie graphique n'est pas le probleme** :
`AVCaptureVideoPreviewLayer` s'attache a une session existante en simple consommateur,
CameraX lie un cas d'usage `Preview` a cote d'`ImageCapture`, Flutter pose une vue de
plateforme. C'est de la plomberie connue.

**Le cout reel est le cycle de vie.** Un apercu fait vivre la session des minutes, et la
capture se produit *pendant*. Ce n'est pas un ajout a `Camera`, c'est un changement de
forme. D'ou la seule question qui compte : **qui possede la session — la vue de
plateforme, ou le coeur ?**

Se tromper produit deux sessions qui se disputent la camera. C'est le mode de defaillance
previsible de toute integration naive, et la raison pour laquelle un integrateur serait
tente d'utiliser `camera.dart` pour l'apercu et le coeur pour la capture.

**A4.2 n'est pas ecrite.** Dans l'etat, l'ecrire trancherait la question **par omission** :
la forme retenue pour la capture Android deviendrait la reponse, sans que personne ne
l'ait choisie. C'est exactement ce qu'ADR-0007 a constate pour le format d'acquisition,
herite au lieu d'etre decide — et la raison pour laquelle cette decision se prend
maintenant plutot qu'apres.

## Decision

1. **Le coeur possede la session. La vue s'y rattache en consommateur.** Sur iOS,
   `AVCaptureVideoPreviewLayer(session:)` pointe la session du coeur. Sur Android, le
   coeur detient la liaison `ProcessCameraProvider` et lie lui-meme `Preview` et
   `ImageCapture` ; la vue ne fournit qu'un `SurfaceProvider`.

2. **Un seul proprietaire, deux points d'entree.** Une session **ephemere** pour une prise
   isolee — l'existant, inchange, et les mesures de C4.2 restent valides — et une session
   **longue** a laquelle un apercu se rattache. La seconde n'est pas un mode different :
   c'est la meme session avec une duree de vie plus longue.

3. **Le coeur reste seul a configurer la sortie photo.** L'apercu ne peut changer ni le
   codec, ni la source, ni la resolution des octets scelles. Un consommateur consomme.

4. **Jamais la trame d'apercu comme octets scelles.** C'est tentant — obturateur
   instantane, cout nul — mais cela fait sortir les octets du pipeline **video** au lieu
   du pipeline photo : autre traitement, autre qualite, et une provenance qui n'est plus
   celle qu'on documente. Regle normative, les deux plateformes.

5. **Le cycle de vie entre dans le coeur, et c'est le prix.** Arriere-plan et retour au
   premier plan, interruptions — appel entrant, autre application prenant la camera —
   rotation et multi-fenetre sur Android. Aucun de ces cas n'existe avec une session
   ephemere ; tous apparaissent avec un apercu.

6. **L'echappatoire reste `seal(bytes)`.** Un integrateur qui veut posseder sa propre
   session ne perd pas le produit : il obtient le profil `core`. Il ne s'agit pas d'un
   mode degrade mais d'une preuve **plus etroite**, et correctement nommee.

## Justification

- **Le point 1 n'arbitre pas entre deux inconvenients : l'autre option dissout ce qu'on
  construit.** Toute la raison d'etre du profil `capture` — specification §2.5, « contenu
  acquis, contenu fourni » — est que **le coeur a observe l'acquisition**. Si l'hote
  possede la session, c'est lui qui choisit la sortie, le format, eventuellement la
  source ; le coeur signe alors des octets dont il n'a pas vu la naissance. C'est `core`
  avec des etapes en plus, et le noter `capture` serait affirmer plus qu'on ne sait.

- **Un second argument, independant du premier : la propriete par la vue contredit
  ADR-0003.** Celui-ci pose que tout le chemin critique reste natif et que le pont Dart/JS
  ne recoit que l'enveloppe signee, opaque. Une session possedee par la vue de plateforme
  mettrait la configuration de l'acquisition — donc une part du chemin critique — dans la
  liaison. Les deux ADR tomberaient ensemble ou tiendraient ensemble ; ils tiennent.

- **Le point 6 est ce qui rend le point 1 tenable.** Le cas d'usage que servirait une
  session possedee par l'hote est **deja servi**, honnetement, par un autre profil. Il n'y
  a donc aucune pression a contorsionner `capture` pour lui, et le refus ne coute aucun
  integrateur — il lui coute un grade, ce qui est le rapport exact entre ce qu'il concede
  et ce que le coeur peut attester.

- **Le point 5 est ecrit pour ne pas etre decouvert.** Le cycle de vie est la seule chose
  que cette decision rend plus chere, et la minimiser serait la reproduire en pire : un
  artefact qu'on veut mince herite d'une plomberie de plateforme reelle. Le nommer ici
  evite qu'il ressorte comme une surprise au milieu d'A4.2.

- **Le point 4 est ecrit avant que quelqu'un ne l'essaie.** L'erreur est seduisante et
  silencieuse : rien ne casse, l'enveloppe se signe, et la provenance annoncee n'est plus
  la vraie. Meme famille que le type MIME parallele qu'ADR-0007 a ferme.

- **L'apercu ne se justifie pas par `media[6]`.** Un apercu supprime de la latence
  **percue** — mise sous tension du capteur, delai de garde, attente 3A — et c'est une
  raison suffisante. Mais `media[6]` part de l'obturateur : ces trois termes n'y ont
  jamais figure. Le raisonnement inverse a ete tenu puis corrige le 2026-08-15 ; il est
  consigne ici pour ne pas etre refait une troisieme fois. `CaptureTimings` dira terme a
  terme s'il existe un gain residuel.

## Consequences

- **`Camera.capture()` devient le cas ephemere d'une forme generale**, au lieu d'etre la
  seule forme. Aucune rupture pour C4.2, dont les mesures restent comparables.

- **A4.2 s'ecrit directement dans cette forme.** Le coeur Android detient la liaison
  CameraX et lie les deux cas d'usage ; la vue ne fournira qu'une surface. Ecrire A4.2 en
  session ephemere puis la reprendre couterait deux fois.

- **La surface publique du coeur gagne un objet a etat.** C'est une premiere : jusqu'ici
  le coeur n'exposait que des operations sans memoire. Une session a un cycle de vie, donc
  des etats invalides possibles, donc une responsabilite d'API qui n'existait pas.

- **Le chantier des liaisons est debloque.** La question qui commandait tout — et qui
  interdisait d'ecrire une ligne de liaison Flutter ou React Native — a une reponse. La
  vue de plateforme est un consommateur, ce qui fixe la forme du pont.

- **Aucun effet sur le format d'enveloppe, le CDDL, ni la notation.** Cette decision porte
  sur la forme de l'API du coeur, pas sur ce qu'il produit. Aucun vecteur d'or n'est
  touche.

- **`docs/acquisition-et-liaisons.md` §2 cesse d'etre une discussion ouverte** et renvoie
  a cet ADR. Sa seconde decision — le niveau vise par une serie hors ligne — reste
  ouverte, et n'est pas tranchee ici.

## Ce qui ferait revenir sur cette decision

Si une plateforme rendait impossible le rattachement d'un apercu a une session detenue par
une bibliotheque — un cadre applicatif exigeant de posseder lui-meme la session —
l'arbitrage se rouvrirait. La reponse serait alors de **retirer l'apercu du coeur**, pas de
ceder la propriete : le point 1 tient sur ce que `capture` affirme, et cela ne se negocie
pas contre une commodite d'integration.

Si un besoin apparaissait ou l'hote doit posseder la camera **et** obtenir le profil
`capture`, ce serait une demande d'affaiblir le profil. Elle se traite en ouvrant un
profil distinct qui dit ce qu'il atteste reellement — jamais en elargissant `capture`,
dont le sens est precisement ce que cet ADR protege.
