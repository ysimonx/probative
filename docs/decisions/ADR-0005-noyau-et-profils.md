# ADR-0005 — Noyau independant du contenu, profils declares

**Statut :** accepte
**Date :** 2026-08

## Contexte

Le format `probative/0.1` n'a qu'une seule forme, et elle est implicite. Le CDDL exige
sans condition `media[5] => [uint, uint]` (largeur, hauteur), definit `media[2]` comme
l'empreinte des « octets bruts du capteur », et rend `position` obligatoire. Le mot
« photo » n'apparait nulle part — l'invariant 3 est respecte — mais la forme decrite n'est
rien d'autre qu'une image geolocalisee.

Or le mecanisme, lui, ignore totalement le type de contenu. R1 vaut
`SHA-256(payload_bytes || nonce)` : des octets quelconques. La cle materielle,
l'attestation, la verification par recalcul ne regardent jamais le payload. Le code
implemente de la provenance d'octets ; le format decrit une prise de vue.

**Ce decalage a un cout mesurable, pas theorique.** `grade_origin` part de `Grade.B` et
n'en sort jamais : `ORIGIN_CAP_V01` est applique inconditionnellement, au motif que la
photographie d'ecran n'est pas detectee. `overall_level` retient la propriete la plus
faible. **Consequence : aucune enveloppe ne peut atteindre `STRONG`, quel que soit son
contenu**, a cause d'un angle mort qui ne concerne qu'une famille de payloads. Un journal
signe, un consentement horodate, un document ne subissent pas cette attaque et sont
plafonnes par elle.

**L'etat de l'art tranche dans le meme sens.** `docs/etat-de-l-art.md` §3 enonce deux
differenciateurs, « pas dix » : la regle R1, et le fait que le serveur juge propriete par
propriete. Ni l'un ni l'autre n'a de rapport avec une image. Ce qui distingue ce depot est
deja independant du contenu ; c'est le cas d'usage qui ne l'est pas.

## Decision

1. **Le format distingue un noyau et des profils.** Le noyau est la couche partagee par
   tout payload : `COSE_Sign1`, `kid` sur la cle attestee, les regles R1/R2/R3, l'empreinte
   du payload, `timing`, `posture`, la preuve de fraicheur, et les proprietes `integrity`
   et `time`. Ce n'est pas un profil, c'est ce que tout profil contient.

2. **Le profil est declare dans l'en-tete protege**, cle `102 => tstr`, et il est
   **obligatoire**. Il n'est **jamais** deduit de la presence ou de l'absence de champs, ni
   supplee par un defaut.

3. **`media[5]` et `position` deviennent optionnels au CDDL**, et sont exiges par le profil
   `capture`. Un champ `media[7]` optionnel porte la duree, pour les mediums temporels.

3 bis. **Le nonce est emis pour un profil, et une enveloppe d'un autre profil est
   rejetee.** Le profil signe dit ce que le client a produit ; le profil du nonce dit ce
   que le serveur a demande.

4. **Un profil se justifie quand une propriete apparait, disparait, ou change de regle de
   notation. Jamais quand seul le payload change de forme.** Un type MIME nouveau ne cree
   pas un profil.

5. **`capture` designe l'acquisition d'un signal du monde physique par un capteur de
   l'appareil** — image, son, video. Pas « capture d'image », et pas non plus « donnees de
   capteurs » au sens large : les mesures de corroboration restent des `claim`, quel que
   soit le profil. Le critere est *le payload est-il susceptible d'etre rejoue devant le
   capteur ?*

6. **L'angle mort est renomme d'apres la menace, pas d'apres le medium.** Ce n'est pas la
   photographie d'ecran, c'est la **recapture analogique** : enregistrer un haut-parleur
   qui rejoue un enregistrement est la meme attaque, avec les memes consequences —
   position authentique, attestation valide, contenu faux. Le plafond appartient au profil
   `capture` tout entier.

7. **L'ensemble des proprietes notees devient fonction du profil.**

## Justification

- **Les points 2 et 3 bis sont le seul vrai enjeu de securite de cet ADR, et il fallait les
  deux.** Un profil deduit des champs presents permettrait de retirer `position` d'une
  acquisition pour la faire juger avec les regles du noyau, echappant au plafond de
  recapture : d'ou le profil dans l'en-tete protege, couvert par la signature. Mais la
  signature ne prouve que la coherence de la declaration, pas sa sincerite — un client
  compromis reste libre de declarer `core` des l'origine pour une acquisition. Seul le
  nonce ferme cette porte : le serveur a demande une acquisition, il doit en recevoir une.
  La specification §6 posait deja que le contexte applicatif est lie par le nonce ; c'en
  est la premiere application concrete.
- **Le label 102 est obligatoire, et non optionnel avec repli sur `core`.** Le modele de
  donnees pose que toute donnee absente vaut `None`, jamais un defaut plausible, « un
  defaut plausible masquerait une omission deliberee ». Un profil absent valant `core`
  serait exactement ce defaut-la, et sur le champ qui determine les regles de notation.
- **Le point 4 evite l'explosion de profils.** Passe au test, l'audio ne justifie pas de
  profil propre : memes proprietes, memes regles de notation, meme corroboration
  barometrique et inertielle, meme menace de recapture. Seul le bloc descriptif change —
  une duree au lieu de dimensions — ce qui releve d'un champ optionnel, pas d'un profil.
  Sans ce critere, le verificateur deviendrait un registre de types MIME.
- **Le point 6 renforce le decoupage plutot qu'il ne le complique.** Le noyau n'est pas
  concerne par la recapture analogique parce qu'il n'affirme rien sur le monde physique.
  C'est precisement ce qui rend le plafond legitime la ou il s'applique, et illegitime
  ailleurs.
- **Invariant 5.** Le resultat reste structure par propriete ; c'est l'ensemble des
  proprietes qui devient dependant du profil. La granularite du verdict n'est pas
  entamee, son perimetre est explicite au lieu d'etre implicite.
- **Invariant 3.** `capture` etait deja le terme impose pour proscrire le vocabulaire
  metier. L'elargir d'« image » a « acquisition physique » va dans le sens de l'invariant,
  il ne le contredit pas.

## Consequences

- **§8 doit etre amendee.** La politique de version stipule qu'un verificateur de version
  mineure inferieure « doit rester capable de valider les quatre proprietes ». L'ensemble
  n'est plus fixe : lire « les proprietes du profil declare ». Un verificateur qui ne
  connait pas un profil doit **refuser de juger**, et non juger avec les regles du noyau —
  ce serait le contournement decrit au point 2, obtenu par simple anciennete du
  verificateur.
- **Pas de changement de version.** `probative/0.1` n'est publiee nulle part et aucun
  verificateur n'est deploye ; le changement est absorbe dans 0.1 plutot que de graver une
  0.2 dont personne n'a la 0.1. Cette latitude disparait a la premiere mise en service.
- **`ORIGIN_CAP_REASON` change de libelle et de portee.** Le noyau devient capable
  d'atteindre `STRONG`, ce qui est aujourd'hui impossible pour tout payload.
- **`grade_origin` se scinde** : la part noyau — application reconnue, integrite du
  materiel, latence — reste ; le plafond migre dans la notation du profil `capture`.
- **Les vecteurs d'or sont regeneres** (`tools/gen_vectors.py`), et un troisieme jeu
  `core` s'ajoute a `android` et `ios`. Il n'est pas decoratif : c'est la seule forme qui
  atteigne `STRONG`, donc la seule qui verifie que le plafond est bien attache au profil
  et non au format. Les vecteurs d'appareil dans `tests/device-vectors/` restent valides :
  ils portent des chaines d'attestation, que ce changement ne touche pas.
- **Les coeurs natifs devront inscrire le label 102 et lire le profil rendu par la route
  `/nonce`.** C'est la seule modification que cet ADR impose a Kotlin et Swift, et elle
  tombe avant A4/C4 — donc avant qu'une capture reelle existe.
- **Les phases B et D ne sont pas concernees.** Dechiffrer un jeton Play Integrity et
  verifier une signature App Attest sont des operations du noyau, indifferentes au profil.
  Cet ADR ne les retarde pas et n'en depend pas.
- **Le profil `capture` reste la demonstration du projet.** Le noyau seul — une signature
  adossee au materiel sur des octets quelconques — est proche de la commodite : Approov,
  WebAuthn/FIDO, DeviceCheck en couvrent des variantes. Ce qui n'est pas commodite, c'est
  R1 et la corroboration de position. Decoupler ne veut pas dire deprioriser `capture` ; il
  veut dire que le noyau cesse d'en payer les couts.

## Ce qui ferait revenir sur cette decision

Si la detection de recapture analogique etait implementee et permettait de lever le
plafond, le motif le plus concret du decoupage disparaitrait. Le point 2 — profil signe
plutot que deduit — resterait neanmoins necessaire des lors qu'il existe plus d'un jeu de
regles de notation.

Si aucun second profil n'emergeait dans les douze mois, l'abstraction serait a considerer
comme non gagnee : conserver la separation dans la notation, et reexaminer l'utilite du
label `102` plutot que de le maintenir par principe.
