# Modèle de menace — Capture photo géolocalisée attestée

**Version 0.2 — bi-plateforme (Android + iOS)**
Statut : brouillon, à réviser après le spike d'attestation natif.
Remplace la v0.1, qui raisonnait par verdict de plateforme.

---

## 1. Objet

Définir ce que la bibliothèque garantit, ce qu'elle ne garantit pas, et à quel coût un attaquant peut la contourner.

Ce document est la spécification de référence. Toute fonctionnalité qui n'y répond pas à une menace identifiée est hors périmètre.

## 2. Ce que l'on cherche à prouver

Une capture valide atteste conjointement de quatre propriétés :

| # | Propriété | Signification |
|---|---|---|
| P1 | **Origine** | L'image provient du capteur de l'appareil, pas d'un fichier ni d'un flux injecté |
| P2 | **Position** | L'appareil se trouvait aux coordonnées déclarées au moment de la capture |
| P3 | **Instant** | La capture a eu lieu dans la fenêtre temporelle attendue |
| P4 | **Intégrité** | Ni l'image ni les métadonnées n'ont été modifiées après la capture |

Ces quatre propriétés sont indissociables : une garantie partielle n'a aucune valeur probante.

## 3. Principes directeurs

> **Le client collecte et signe des preuves. Le serveur juge.**

Aucune décision de validité n'est prise sur l'appareil. Le code client est intégralement considéré comme hostile : il s'exécute sur du matériel contrôlé par l'attaquant, il est décompilable et instrumentable à l'exécution.

> **Le format raisonne en propriétés, pas en plateformes.**

Android et iOS n'exposent pas les mêmes signaux. Le format ne doit donc pas décrire *quels capteurs ont répondu*, mais *quelles propriétés sont établies et par quelles preuves*. Une plateforme atteint un niveau par les moyens dont elle dispose.

Corollaires contraignants :

- l'API publique n'expose **jamais** de valeur booléenne de confiance ;
- la clé privée de signature est générée dans le composant matériel sécurisé, non exportable, et n'est jamais manipulée par le code Dart ;
- toute capture répond à un **nonce fourni par le serveur** ;
- l'horodatage client est un signal, jamais une preuve ;
- la corroboration est une **liste de réclamations optionnelles typées**, jamais un objet à champs fixes.

## 4. Profils d'attaquant

### A1 — Opportuniste
Utilisateur légitime qui cherche à s'épargner un déplacement. Installe une application de faux GPS, ou photographie un écran.

*Compétence : faible. Outillage : applications grand public.*

**Asymétrie de plateforme notable.** Sur Android, ce profil est accessible en trois minutes depuis le store. Sur iOS non jailbreaké, la falsification de position exige un ordinateur relié en USB et un outillage de développement : A1 est largement hors-jeu par construction. En revanche, la photographie d'écran reste triviale sur les deux.

**Objectif : blocage total.**

### A2 — Technicien
Sait rooter ou jailbreaker un appareil, installer un module d'injection, utiliser un framework d'instrumentation dynamique. Suit des tutoriels, n'en écrit pas.

*Compétence : moyenne. Outillage : public, documenté.*

**Objectif : détection systématique et refus.** On ne cherche pas à empêcher l'exécution, on cherche à la rendre visible.

### A3 — Organisé
Fraude en volume, budget matériel dédié. Peut acquérir des appareils au bootloader déverrouillable, patcher des images système, développer ses propres hooks, acquérir un simulateur GNSS.

*Compétence : élevée. Motivation : gain financier récurrent.*

**Objectif : rendre l'attaque plus coûteuse que la réalisation honnête, et détectable statistiquement au niveau de la flotte.**

### A4 — Hors périmètre
Accès physique prolongé à un appareil dont le démarrage sécurisé est compromis, ou chaîne d'exploitation zero-day de l'élément sécurisé.

**Non couvert. Assumé et documenté.**

---

## 5. Preuves par propriété

Pour chaque propriété, les moyens dont dispose chaque plateforme. Le grade indique la force de la preuve, pas la quantité de signaux.

### P1 — Origine de l'image

| | Android | iOS |
|---|---|---|
| Capture | CameraX / Camera2, bytes bruts empreintés en natif avant tout passage en Dart | AVFoundation, idem |
| Accès galerie | Aucune permission de lecture du stockage | Aucune permission photothèque |
| Binaire authentique | Play Integrity, verdict `PLAY_RECOGNIZED` | App Attest, attestation liée à l'App ID |
| Caméra virtuelle | Détectée indirectement via l'échec d'intégrité de l'appareil | Nécessite un jailbreak → heuristiques + échec App Attest |
| **Grade atteignable** | **B** | **B** |

*Plafonné à B sur les deux plateformes tant que la photographie d'écran n'est pas traitée.*

### P2 — Position

| | Android | iOS |
|---|---|---|
| Source primaire | FusedLocationProvider + LocationManager comparés | CoreLocation |
| Détection de mock | `isFromMockProvider`, mode développeur, inventaire de paquets | **Indisponible** |
| Altitude corroborée | Baromètre | `CMAltimeter` — précision supérieure |
| Cinématique | Accéléromètre / gyroscope | `CMPedometer` + `CMMotionActivity` — plus fiables |
| Intégrité de l'environnement | Play Integrity | App Attest + détection de débogueur (`P_TRACED`) |
| **Grade atteignable** | **A** | **A** |

**Stratégies inversées.** Android détecte directement la falsification mais l'indicateur est lui-même contournable : le poids porte sur l'attestation. iOS n'a aucun indicateur de mock mais dispose de capteurs inertiels difficiles à falsifier sans jailbreak : le poids porte sur la corroboration physique. Les deux atteignent le même grade par des chemins opposés.

### P3 — Instant

| | Android | iOS |
|---|---|---|
| Horloge monotone | `SystemClock.elapsedRealtime()` | `ProcessInfo.systemUptime` |
| Écart horloge murale / monotone | Signal exploitable | Signal exploitable |
| Ordonnancement serveur | Nonce à fenêtre de validité | Nonce + **compteur d'assertion App Attest** |
| **Grade atteignable** | **B** | **A** |

*Le compteur d'assertion App Attest, strictement croissant et vérifié côté serveur, donne à iOS une garantie d'ordonnancement qu'Android n'a pas nativement. C'est le seul point où iOS est structurellement supérieur.*

### P4 — Intégrité

| | Android | iOS |
|---|---|---|
| Empreinte | SHA-256 des bytes bruts, calculée en natif | Identique |
| Signature | Clé EC non exportable, Keystore / StrongBox, `setAttestationChallenge` | Clé App Attest, Secure Enclave |
| Enveloppe | COSE_Sign1 | COSE_Sign1 |
| **Grade atteignable** | **A** | **A** |

---

## 6. Niveaux de confiance restitués

Le vérificateur retourne un niveau global, dérivé des grades par propriété. Le niveau global est celui de la **propriété la plus faible** : une chaîne vaut son maillon le plus faible.

| Niveau | Conditions |
|---|---|
| `STRONG` | Les quatre propriétés au grade A ou B, attestation matérielle valide, capture en ligne avec nonce frais, corroboration inertielle cohérente |
| `STANDARD` | Attestation valide, une propriété au grade C par absence de capteur (baromètre indisponible sur l'appareil) |
| `DEGRADED` | Capture hors ligne dans la fenêtre autorisée, ou corroboration partiellement absente |
| `UNTRUSTED` | Attestation absente ou invalide, mock détecté, incohérence cinématique, débogueur attaché |
| `REJECTED` | Signature invalide, nonce inconnu ou expiré, empreinte non concordante, compteur d'assertion non croissant |

Aucun niveau ne dépend du système d'exploitation. Un appareil Android et un iPhone peuvent tous deux atteindre `STRONG`.

## 7. Limites assumées

1. Un simulateur GNSS matériel produit un signal indiscernable côté client, sur les deux plateformes. Seule la détection statistique serveur, sur historique de flotte, offre une prise.
2. **La photographie d'un écran n'est pas détectée en v0.1.** Le GPS est authentique, l'attestation est valide, seul le contenu est faux. Aucun signal de position ne la révèle. C'est le principal angle mort, à traiter en priorité.
3. Les appareils Android sans services Google Play ne peuvent pas être attestés et sont classés `UNTRUSTED` par construction, ce qui exclut une partie du parc.
4. Sur iOS, la détection de jailbreak relève de l'heuristique et se contourne. La garantie repose donc sur l'échec d'App Attest, pas sur cette détection.
5. Un appareil compromis n'est pas empêché de fonctionner ; il est détecté et refusé. Si la détection est contournée, la garantie tombe entièrement.
6. La bibliothèque ne prouve pas l'**identité** de l'opérateur. Elle prouve qu'un appareil donné était à un endroit donné à un instant donné.

## 8. Exigences non fonctionnelles

- **Hors ligne** : capture possible sans réseau, avec provision de nonces pré-délivrés et niveau dégradé au-delà d'un délai paramétrable.
- **Minimisation** : aucune donnée de tiers en clair. Les identifiants d'infrastructure environnante, s'ils sont collectés en v0.2, sont hachés avec un sel propre à chaque déploiement.
- **Vie privée** : la position n'est collectée qu'à l'instant de la capture, jamais en continu, jamais en arrière-plan.
- **Auditabilité** : le format d'enveloppe est public et versionné ; une capture doit rester vérifiable indépendamment de l'implémentation qui l'a produite.
- **Extensibilité** : l'ajout de réclamations de corroboration ne doit jamais constituer un changement cassant.

## 9. Critères de validation

Le modèle est tenu lorsque le banc de test démontre, **sur appareils physiques des deux plateformes** :

- [ ] A1 bloqué sur l'intégralité de son profil, sans exception
- [ ] A2 détecté et refusé sur l'intégralité de son profil
- [ ] Une enveloppe modifiée d'un seul octet est rejetée
- [ ] Une enveloppe rejouée avec un nonce périmé est rejetée
- [ ] Une assertion iOS au compteur non croissant est rejetée
- [ ] Une capture sur émulateur ou simulateur est rejetée
- [ ] Un même scénario terrain honnête produit le même niveau sur les deux plateformes
- [ ] Le taux de faux positifs sur appareils sains reste sous 1 %, mesuré séparément par plateforme

---

## 10. Conséquences pour le format d'enveloppe

Ce modèle impose trois contraintes de conception :

1. **Aucun champ obligatoire propre à une plateforme.** `mock_provider` et le verdict Play Integrity sont des réclamations optionnelles, au même titre que le compteur App Attest.
2. **Chaque réclamation porte son type, sa source et sa confiance.** Le vérificateur score ce qu'il reçoit et ignore ce qu'il ne connaît pas.
3. **Le résultat de vérification est structuré par propriété.** Le serveur appelant doit pouvoir savoir *laquelle* des quatre propriétés est faible, pas seulement qu'un score global est bas.

---

*Prochaine révision : après le spike d'attestation natif. Les verdicts Play Integrity et les taux d'échec App Attest réellement obtenus peuvent invalider les hypothèses des sections 5 et 6.*
