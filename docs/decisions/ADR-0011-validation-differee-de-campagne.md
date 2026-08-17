# ADR-0011 — Validation differee : recuperer en ligne ce que le hors ligne ne peut pas dire

**Statut :** accepte
**Date :** 2026-08

## Contexte

ADR-0010 rend la capture hors ligne possible sur Android par l'attestation de cle, et
conclut qu'elle plafonne a `DEGRADED` : hors ligne, rien ne peut etablir « ce binaire est
celui que Play distribue », et `origin` retombe sur le cas d'un binaire signe par le
deploiement.

**Cette conclusion supposait que le hors ligne est un etat permanent. Il ne l'est pas.**

Le parcours reel du projet cible est en deux temps : l'operateur prend ses photos sur le
terrain, souvent sans reseau, puis **valide sa campagne** — et a ce moment-la, il a une
connexion. La validation n'est pas un geste invente pour les besoins de la preuve : c'est
un moment du produit, qui existerait de toute facon.

**Or `requestHash` est fourni par le client.** Rien n'oblige a demander le jeton Play
Integrity au moment de la capture. A la validation, l'application peut demander un jeton
dont le `requestHash` vaut exactement le R1 d'une enveloppe scellee deux heures plus tot.
La liaison au contenu est identique a celle du mode en ligne ; seul l'instant differe.

**Et l'en-tete de fraicheur n'est pas couvert par la signature.** C'est ecrit en spec §2.2
et cela a toujours ete presente comme une non-faiblesse — le jeton se lie lui-meme au
contenu par R1. La consequence n'avait pas ete tiree : **on peut y ajouter quelque chose
apres coup sans invalider l'enveloppe.**

## Decision

1. **La validation est un second temps, et elle produit une preuve de fraicheur
   supplementaire.** A la reprise du reseau, l'application obtient un ou plusieurs jetons
   Play Integrity dont le `requestHash` vaut le R1 des enveloppes deja scellees.

2. **Le jeton differe voyage dans l'en-tete non protege, sous un label distinct** —
   `? 201 => freshness`. Distinct de `200` et non cumule avec lui, parce que les deux ne
   disent pas la meme chose au meme instant : `200` atteste la capture, `201` atteste la
   validation. Les confondre ferait perdre l'ecart, qui est precisement ce qui se note.

3. **R1 est inchangee.** Le `requestHash` du jeton differe vaut `SHA-256(payload ‖ nonce)`
   de l'enveloppe qu'il accompagne — recalcule par le serveur, jamais lu. Invariant 2
   intact.

4. **Un jeton par enveloppe est la norme.** Chaque enveloppe obtient alors son propre
   `app-recognized` et son propre verdict d'appareil, lies a sa propre charge utile.

5. **Un jeton unique pour la campagne est un repli documente**, dont le `requestHash` vaut
   l'empreinte de la **derniere** enveloppe de la chaine. Le chainage rend cette couverture
   transitive : l'enveloppe N contient l'empreinte de N-1, donc l'empreinte de N s'engage
   sur toute la suite. **Le repli n'est donc pas plus faible cryptographiquement — il est
   plus fragile** : un maillon rompu prive de liaison tout ce qui le precede, la ou des
   jetons individuels resisteraient.

6. **Le verdict d'appareil d'un jeton differe date de la validation, pas de la capture.**
   Il n'atteste pas l'etat de l'appareil au moment de la prise ; c'est le `RootOfTrust`
   frais de l'attestation de cle qui s'en charge (ADR-0010 point 5). **Les deux se
   completent, aucun ne remplace l'autre.**

7. **L'ecart entre capture et validation se note sur sa largeur observee**, jamais sur un
   drapeau. Le serveur connait l'instant d'emission du nonce ; le jeton porte le
   `timestampMillis` de Google. Une campagne validee dans l'heure ne vaut pas une campagne
   validee trois semaines plus tard, et le grade suit continument. **Invariant 8.**

8. **La validation n'est jamais exigee.** Une campagne qui ne serait jamais validee reste
   verifiable sur sa seule attestation de cle, au niveau qu'ADR-0010 lui donne. La
   validation **enrichit** ; elle ne conditionne pas.

## Justification

- **Le point 2 est ce qui rend la decision peu couteuse, et il tenait dans une propriete
  qu'on avait sous les yeux.** L'en-tete non protege est le seul endroit d'une enveloppe
  COSE ou l'on peut ecrire apres signature. La specification le presentait comme une
  non-faiblesse ; c'est en fait une capacite, et elle sert exactement ici. Aucune
  re-signature, aucune enveloppe parallele, aucun fichier compagnon a ne pas perdre.

- **Le point 4 preferé au point 5, et le point 5 conserve quand meme.** Un jeton par
  enveloppe est plus robuste et le quota ne s'y oppose plus : la mesure du 2026-08-17 a
  montre que le bridage venait des `prepare` repetes, faits une fois, et non des demandes
  de jeton. Le repli reste ecrit parce qu'une campagne de cent prises sur un lien
  intermittent est un cas ou l'on sera content de l'avoir.

- **Le point 6 evite la confusion la plus tentante.** Un jeton differe *ressemble* a une
  preuve de l'etat de l'appareil pendant la campagne ; il n'en est pas une. Un appareil
  compromis entre la capture et la validation rendrait un jeton parfaitement sain. Ce que
  la capture garde en propre — le `RootOfTrust` inscrit par le TEE a la generation de la
  cle — est precisement ce que le jeton differe ne peut pas dire.

- **Le point 7 est la quatrieme application de l'invariant 8 en un mois.** `offline: bool`,
  « serie close ou non », le plafond forfaitaire sur nonce pre-delivre, et maintenant
  l'ecart de validation. A chaque fois la tentation etait un drapeau, et a chaque fois la
  grandeur etait mesurable.

- **Le point 8 preserve une propriete du produit qui n'est pas negociable.** Une preuve
  qui n'existerait qu'apres validation ferait perdre les captures d'un operateur qui casse
  son telephone avant de rentrer. L'enveloppe vaut ce qu'elle vaut des la capture ; le
  reseau ameliore, il ne conditionne pas.

- **Le relais reste possible et n'est pas aggrave.** Valider depuis un appareil sain des
  captures faites ailleurs est concevable — mais rien ne lie deja le jeton Play Integrity
  a la cle de signature enrolee, y compris en mode en ligne. Le differe herite de cette
  faiblesse, il ne la cree pas.

## Consequences

- **Le CDDL gagne un label optionnel**, `? 201 => freshness`, dans l'en-tete non protege.
  Additif : une enveloppe v0.1 existante reste valide.

- **L'asymetrie du hors ligne se referme largement.** ADR-0010 point 9 constatait
  qu'Android hors ligne plafonne a `DEGRADED` la ou iOS atteint `STANDARD`. Avec la
  validation, Android recupere `app-recognized` et son verdict d'appareil : l'ecart ne
  subsiste que pour une campagne **jamais validee**, ce qui devient un cas de bord plutot
  qu'un regime.

- **iOS y gagne aussi, marginalement.** App Attest lui donne deja tout hors ligne, mais un
  jeton differe ajouterait un verdict d'appareil que la plateforme n'a pas. A instruire
  separement ; rien ici ne l'exige.

- **Le verificateur gagne un second passage de fraicheur**, sur le meme code : le label 201
  se verifie exactement comme le 200, avec le meme recalcul de R1. Ce qui change est la
  notation, qui doit distinguer les deux instants et mesurer leur ecart.

- **Le coeur gagne une operation de campagne** — reprendre des enveloppes scellees,
  demander leurs jetons, les inserer dans l'en-tete non protege. Elle ne touche pas au
  chemin de capture, et c'est ce qui la rend sans risque pour `media[6]`.

- **La question du lot de nonces revient, et elle est maintenant la seule qui reste.**
  Capturer hors ligne suppose des nonces pre-delivres ; leur largeur d'encadrement est
  desormais notee (ADR-0010 point 7) plutot que plafonnee, mais le dimensionnement du lot
  — combien, pour combien de temps — n'est pas tranche.

## Ce qui ferait revenir sur cette decision

Si Google liait un jour son jeton a la cle materielle de l'appareil, le relais
disparaitrait et le jeton differe deviendrait aussi fort qu'un jeton simultane. Le point 6
perdrait alors sa raison d'etre, et la distinction entre `200` et `201` se reduirait a
l'ecart temporel.

Si la validation s'averait, a l'usage, systematiquement immediate — l'operateur revenant
en zone couverte dans la minute —, la distinction des deux labels resterait juste mais
cesserait d'etre utile, et l'on pourrait envisager de n'en garder qu'un. Ce serait un
appauvrissement du format decide sur une statistique d'usage : a ne faire qu'avec des
mesures, pas avec une impression.

Si une campagne devait pouvoir etre validee **par un tiers** — un bureau qui recoit les
enveloppes d'un operateur —, le jeton differe cesserait d'attester quoi que ce soit de
l'appareil de capture, et il faudrait le dire dans la notation plutot que de laisser croire
l'inverse.
