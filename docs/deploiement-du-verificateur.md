# Déploiement du vérificateur — trois formes, et ce qui les distingue vraiment

**Ouvert le 2026-08-19, sans autorité.** Constats et arbitrage produit, pas un ADR :
aucun de ces choix ne touche le format, et rien n'oblige à choisir une fois pour toutes.
Ce document existe pour que la question « qui fait tourner le juge ? » — posée en
préparant la liaison Flutter — ne se réinstruise pas à chaque fois qu'elle revient.

La réponse courte : les deux modèles évidents (l'intégrateur héberge, l'éditeur héberge)
existent bien, plus un troisième qu'on oublie — la bibliothèque embarquée — qui est
probablement la forme de moindre friction. Le format les permet tous les trois par
construction, et la seule vraie adhérence n'est pas technique : c'est la délégation
d'identifiants Google.

## Ce que le format garantit déjà, et qui rend le choix réversible

- **Invariant 7 : l'enveloppe s'authentifie par elle-même.** Le verdict ne dépend
  d'aucune propriété du canal — c'est précisément ce qui autorise à changer d'hébergeur
  de vérificateur sans toucher ni au client ni au format. Côté client, changer de forme
  de déploiement se résume à changer une URL.
- **ADR-0006 : l'authentification Google est injectable.** Écrite pour ne rien imposer
  aux déploiements, c'est elle qui rend les trois formes possibles côté code : le
  vérificateur reçoit ses identifiants, il ne les possède pas.
- **Le couplage client → vérificateur est minuscule** : trois routes — enrôlement,
  émission de nonce, remise d'enveloppe. Le serveur de développement
  (`probative.devserver`) en est l'implémentation de référence.

**Mais l'état vit chez le juge, et c'est la limite de cette réversibilité.** Quatre
choses n'existent que dans la base du vérificateur : les nonces (R3 — émis par lui, à
usage unique, et **sa** horloge définit la largeur d'encadrement notée), le registre
d'enrôlement (`kid` → clé publique attestée, clé App Attest côté iOS), l'état de
chaînage, et les compteurs d'assertion. Conséquence à ne pas découvrir tard : **la
preuve est portable, le contexte de jugement ne l'est pas.** Une enveloppe ne peut être
rejugée par un autre vérificateur que si le registre d'appareils l'accompagne — sans la
clé publique enrôlée, R2 n'est pas vérifiable.

## Forme 1 — la bibliothèque embarquée

Le vérificateur est un paquet Python : l'intégrateur monte les trois routes dans son
backend existant plutôt que d'exploiter un service de plus. C'est la forme de moindre
friction du self-host, et celle que le README cible de la liaison Flutter devrait
mentionner explicitement.

- **Identifiants** : le chemin naturel — son propre compte de service, sur son propre
  projet Cloud, celui-là même que sa Play Console lie à son application. Aucune
  délégation à personne.
- **Données** : les photos géolocalisées ne quittent pas son infrastructure. C'est
  l'argument RGPD fort, et c'est la promesse que porte le README cible (« envelopes are
  judged on *your* infrastructure »).
- **Coût** : l'intégration des trois routes et le câblage d'authentification — la
  journée estimée au tableau de coût du README cible.

## Forme 2 — le serveur autonome self-host

Même modèle de confiance que la forme 1, exploitation séparée : un service dédié
(`probative-verifier serve`), sa base, sa supervision. Se justifie quand plusieurs
applications du même intégrateur partagent un vérificateur, ou quand le backend
principal n'est pas en Python. Ne change rien au raisonnement — tout ce qui vaut pour
la forme 1 vaut ici.

## Forme 3 — le vérificateur mutualisé (hébergé par l'éditeur)

Techniquement viable, et trois conséquences à regarder en face avant de le promettre :

- **Les identifiants Google ne se mutualisent pas tout seuls.** `decodeIntegrityToken`
  exige des identifiants autorisés sur le projet Cloud **de l'application attestée** —
  qui appartient au tenant, pas à l'opérateur. Deux voies : le tenant délègue l'accès au
  compte de service de l'opérateur dans son projet, ou lui confie une clé de compte de
  service. ADR-0006 rend l'injection par tenant triviale côté code ; **le coût est
  administratif, et c'est une étape d'onboarding réelle**, pas un formulaire.
- **L'état devient multi-tenant et les données personnelles transitent par
  l'opérateur.** Photos et positions traversent son infrastructure : contrat de
  sous-traitance de données obligatoire, et la promesse « rien ne transite ailleurs »
  tombe pour cette forme — le README devra dire l'une ou l'autre, jamais les deux.
- **Les quotas Play Integrity ne s'agrègent pas.** Le plafond journalier est celui du
  projet de chaque application (voir `play-integrity-sessions-et-series.md` §2) :
  mutualiser le vérificateur ne mutualise aucun quota. La borne d'architecture
  *N appareils × M captures/jour* reste par tenant.

Ce que cette forme est seule à offrir : **un verdict rendu par un tiers.** Voir
ci-dessous — c'est le vrai axe de différenciation, pas l'hébergement.

## L'opposabilité est le vrai axe, pas l'hébergement

La spec §9 le dit déjà pour l'horodatage : l'encadrement par le nonce est « une preuve
que le serveur se fabrique à lui-même ». Quand l'intégrateur self-host **et** est le
bénéficiaire de la preuve, son vérificateur juge sa propre cause. Trois positions, en
force croissante :

| Qui juge | Ce que vaut le verdict devant un tiers |
|---|---|
| Le bénéficiaire (formes 1 et 2) | Auto-produit. Mitigation prévue : les deux jetons RFC 3161 de l'inconnue n° 4 — un tiers accrédité contresigne les bornes, sans devenir juge |
| Un opérateur neutre (forme 3) | Verdict d'un tiers non accrédité : mieux, sans supprimer l'intérêt de RFC 3161 |
| Un tiers accrédité | Hors de portée d'un dépôt — c'est la piste réglementaire de la spec §9 et de `certification-anssi.md` |

Corollaire commercial à ne pas inverser : la forme 3 ne se vend pas comme « plus
simple » — sa simplicité est mangée par l'onboarding d'identifiants — mais comme
« un juge qui n'est pas vous ». Et RFC 3161 rend aux formes 1 et 2 une partie de cet
argument : les deux chantiers se complètent, aucun ne remplace l'autre.

## Ce qui ferait de cette question un ADR

Rien, tant que le format n'est pas touché. Le jour où une offre mutualisée semblerait
exiger un identifiant de tenant **dans l'enveloppe**, la réponse est déjà écrite :
c'est de la famille de l'identifiant de session refusé par ADR-0009 — le rattachement
d'un tenant est du déploiement (une clé d'API sur les trois routes), jamais du format.
Si cette réponse ne suffisait pas, c'est là qu'un ADR s'ouvrirait, pas avant.

## Renvois

- Invariant 7 (`CLAUDE.md`), spec §6 — le verdict ne dépend jamais du canal
- `docs/decisions/ADR-0006-authentification-google-injectable.md` — le point d'injection
  qui rend les trois formes possibles
- `docs/play-integrity-sessions-et-series.md` §2 — quotas, coût unitaire du verdict
  d'appareil, borne *N × M*
- `docs/envelope-spec.md` §9 et inconnue n° 4 (`CLAUDE.md`) — RFC 3161, la forme complète
  à deux jetons
- `docs/liaison-flutter-readme-cible.md` — le tableau de coût d'intégration que ces
  formes font varier, et la promesse de localisation des données à accorder
- `docs/certification-anssi.md` — la marche au-dessus : le tiers accrédité
