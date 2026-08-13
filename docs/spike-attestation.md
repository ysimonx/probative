# Plan du spike d'attestation natif

**Statut : en cours — document de pilotage.** Les cases sont cochées au fur et à
mesure ; une tâche abandonnée ou modifiée est barrée avec une note, jamais effacée
silencieusement. Ce qui relève d'une décision durable part en ADR à la clôture.

## Objectif et critère de sortie

Produire, depuis un appareil réel — Android d'abord, iOS ensuite — une enveloppe
`probative/0.1` que le vérificateur Python accepte. Critère binaire : la boucle
« capture sur appareil → enveloppe → vérification serveur » passe au vert avec la
validation d'attestation **réelle** (étape 5 du pipeline), pas le substitut.

`verifier-python/tests/factory.py` reste l'implémentation de référence : si le natif
produit une enveloppe que la fabrique ne saurait pas produire, c'est le natif qui
s'écarte de la spécification. Les cœurs sont des artefacts autonomes — AAR,
XCFramework — sans dépendance à un framework (ADR-0003).

## Inconnues que le spike doit lever

1. **`requestHash` Play Integrity.** ~~L'API standard prend une *chaîne* (≤ 500
   octets documentés) ; R1 produit un condensat de 32 octets *bruts*.~~
   **Levée sur la taille le 2026-08-11** (SM-X200) : base64url sans bourrage donne
   43 caractères, très en deçà du plafond. Le condensat passe tel quel, aucun
   niveau d'indirection, la spec §3/R1 tient.
   ~~Reste à confirmer que Play restitue la chaîne intacte.~~
   **Close le 2026-08-12 : l'aller-retour est vérifié.** Un jeton réel déchiffré par
   Google restitue un `requestHash` identique au R1 recalculé côté hôte. Reste à
   rendre l'encodage normatif dans ADR-0002 — formalité, plus une inconnue.
2. **Latence capture→signature (`media.6`)** sur appareil d'entrée de gamme : elle
   conditionne l'exploitabilité du champ comme discriminant d'injection.
3. **Chaînage Android** (spec §9) : chaîne de hachage locale ou compteur Keystore.
   Le spike implémente la chaîne locale et documente ce qui pousserait vers l'autre.

---

## Phase 0 — Outillage de vérification (`verifier-python`)

Aucun matériel requis. Donne aux appareils réels une cible à viser.

### 0.1 Vecteurs d'or

La canonicité CBOR (spec §7) se teste octet à octet, pas par relecture. Une clé
logicielle **déterministe et de test** est utilisée : ce n'est pas du matériel
cryptographique réel au sens du `.gitignore`, et le fichier le dit en tête.

- [x] `tools/gen_vectors.py` : à partir de `factory.py` avec clé EC déterministe,
      nonce et horloges figés, écrit `payload_bytes`, `protected_bytes`,
      `sig_structure`, le défi R1 et l'enveloppe complète dans
      `verifier-python/tests/vectors/`. La signature des vecteurs est en ECDSA
      déterministe (RFC 6979) — sans quoi l'enveloppe changerait à chaque
      génération ; les appareils, eux, signent en ECDSA aléatoire.
- [x] Deux jeux : un `android` (chaînage, posture 6/7/8), un `ios` (compteur,
      posture 9), pour couvrir les deux formes de charge utile.
- [x] Test pytest qui régénère et compare (`test_vectors.py`) — et qui vérifie
      aussi que les enveloppes des vecteurs sont *acceptées* par le pipeline,
      pas seulement stables.
- [x] Pièges d'encodage documentés dans `tests/vectors/README.md`. Constat
      notable : les trois largeurs de flottants coexistent dans un même vecteur
      (`8.0` → float16 `f94800`, `48.2973` → float64) — les encodeurs natifs
      devront implémenter la demi-précision.

### 0.2 Serveur de développement

Câblage du `Verifier` existant, aucune décision de validité nouvelle.

- [x] Socle retenu : **bibliothèque standard** (`http.server`), corps JSON avec
      octets en base64 — ~~extra optionnel `[devserver]` (FastAPI + uvicorn)~~
      abandonné : zéro dépendance nouvelle pour trois routes, cohérent avec la
      surface minimale d'ADR-0001. Module `probative.devserver`, hors API
      publique.
- [x] `POST /enroll` : clé publique X9.62 + plateforme → calcul du `kid`
      (SHA-256, comme `factory.kid_for`), `DeviceRecord` en mémoire. La chaîne
      d'attestation de clé est acceptée sans validation en phase 0 (validation
      réelle : phases B et D).
- [x] `POST /nonce` : émission d'un nonce à durée de vie courte via
      `InMemoryNonceStore`.
- [x] `POST /verify` : enveloppe + média, retourne le résultat structuré JSON
      (niveau, grades par propriété, `level_reason`, drapeaux).
- [x] `NullAttestationVerifier` par défaut, remplaçable par les vérificateurs réels
      des phases B et D sans toucher aux routes (paramètre du `DevService`).
- [x] Tests : boucle complète fabrique → HTTP → `STANDARD`, rejeu → `REPLAYED_NONCE`,
      nonce inconnu, clé non enrôlée, erreurs de transport (400/404).
- [x] Doc de lancement et exemple `curl` complet dans `verifier-python/README.md`.

**Sortie de phase 0 : atteinte (2026-08-06).** Une enveloppe de la fabrique passe
par HTTP de bout en bout ; les vecteurs d'or sont versionnés et testés. 50 tests,
ruff et mypy au vert.

---

## Phase A — Cœur Android (`mobile/android/`)

Projet Gradle : module `:core` publiable en AAR, sans dépendance UI ni framework ;
module `:demo`, application minimale qui consomme l'AAR et parle au serveur de dev.

### A1 — Squelette du projet

- [x] `settings.gradle.kts`, `:core` (bibliothèque Android, Kotlin pur). Le module
      ~~`:demo` (application)~~ est différé à A4 : rien à démontrer avant la
      capture, et un module vide n'aurait fait qu'alourdir le build.
- [x] `minSdk` fixé à 26. Outillage retenu : Gradle 8.14.3 (wrapper officiel),
      AGP 8.10.1, Kotlin 2.1.21, JDK 17, compileSdk 36. `local.properties` non
      versionné (chemin SDK propre à la machine).
- [x] `./gradlew :core:assembleRelease` produit un AAR consommable seul (12 Ko ;
      seule dépendance d'exécution : kotlin-stdlib, aucune dépendance framework) —
      condition ADR-0003 vérifiée dès le squelette.

### A2 — Encodeur CBOR canonique + COSE_Sign1 en Kotlin

Strict nécessaire, dans l'esprit de `cose.py` serveur (ADR-0001 : surface minimale,
pas de bibliothèque généraliste).

- [x] Encodeur CBOR (`core/cbor/Cbor.kt`) : uint/nint, bstr, tstr, tableau, map
      (ordre canonique RFC 8949 §4.2.1), bool, **float16**/float32/float64 en forme
      la plus courte, tag 18. Types hors format rejetés bruyamment ; conformité
      vérifiée sur les exemples normatifs de la RFC (annexe A).
- [x] `Sig_structure` et assemblage `COSE_Sign1` (`core/cose/Cose.kt`).
- [x] Conversion signature DER → brute `r‖s` 64 octets, validée par croisement
      avec le fournisseur JCA `SHA256withECDSAinP1363Format`.
- [x] Tests unitaires contre les vecteurs d'or, octet à octet, jeux android et ios
      — lus directement dans `verifier-python/tests/vectors/` (source unique,
      chemin injecté par Gradle). 13 tests, dont l'enveloppe complète recomposée
      autour de la signature prélevée du vecteur.

### A3 — Clé matérielle et enrôlement

*Code écrit à l'aveugle le 2026-08-06 (`core/keys/`). **Validé sur appareil réel le
2026-08-11** : Samsung SM-X200, 3 tests instrumentés, 0 échec, 0 sauté.*

- [x] Génération ES256 Keystore, `setAttestationChallenge(nonce)`, StrongBox si
      disponible avec repli documenté, `setUserAuthenticationRequired(false)`.
      Le repli a effectivement servi : la SM-X200 n'expose pas
      `android.hardware.strongbox_keystore`, la clé sort en `TRUSTED_ENVIRONMENT`.
      Le double filet (`StrongBoxUnavailableException` **et** `ProviderException`)
      était la bonne intuition.
- [x] Export de la clé publique X9.62 non compressée, `kid` = SHA-256 — validé sur
      l'hôte JVM contre le couple (clé, kid) du manifest des vecteurs, plus cadrage
      des coordonnées courtes sur 64 clés aléatoires. Confirmé sur appareil :
      65 octets, préfixe `0x04`, `kid` de 32 octets.
- [x] Appel `POST /enroll` du serveur de dev, chaîne de certificats transmise.
      Serveur et appareil calculent le **même `kid`** : la règle R2 tient de bout
      en bout, journal serveur à l'appui (`POST /enroll 200`).
      ~~(validée en phase B seulement)~~ — **validée pour de bon le 2026-08-12** :
      la chaîne est confrontée aux racines publiées par Google et le serveur
      répond `attested: true`. 5 tests instrumentés, **0 échec et 0 saut**, ce
      dernier chiffre étant le seul qui prouve que l'enrôlement n'a pas été
      escamoté par `assumeTrue`.
- [x] Test instrumenté sur appareil : la clé est bien `hardware-backed`
      (`KeyInfo.securityLevel`). Chaîne d'attestation d'au moins 2 certificats ;
      signature brute de 64 octets reconvertie en DER et acceptée par le
      fournisseur JCA.

Point de méthode : le serveur de dev a été rendu joignable par
`adb reverse tcp:8765 tcp:8765` plutôt que par `--host 0.0.0.0`. C'est plus simple
(aucune adresse IP à relever, appareil et hôte n'ont pas besoin d'être sur le même
réseau) et cela évite d'exposer le serveur sur le réseau local. À préférer dans le
commentaire d'en-tête de `KeystoreKeysDeviceTest`.

- [x] **Vecteur d'appareil capturé** (`KeystoreVectorDeviceTest`, 2026-08-11) —
      pendant de la sonde C3 côté iOS. Chaîne de 4 certificats conservée dans
      `tests/device-vectors/`. Contrôle décisif fait **par recalcul** : le défi
      inscrit par le TEE dans l'extension `1.3.6.1.4.1.11129.2.1.17` vaut bien
      `SHA-256(payload ‖ nonce)`, et `attestationSecurityLevel` confirme
      `TrustedEnvironment` dans l'attestation elle-même, pas seulement d'après ce
      que déclare l'appareil.

**Sortie de A3 : atteinte (2026-08-11).** Deux réserves explicites : aucun appareil
doté de StrongBox au banc, donc ce chemin n'est pas exercé — seul le repli l'est ; et
~~la chaîne d'attestation est **cohérente avec elle-même mais sans ancre**~~ —
**réserve levée le 2026-08-12** : la racine du vecteur SM-X200 est confrontée aux
racines publiées par Google et les rejoint, l'ancrage portant sur la clé publique.
Voir phase B. Seule subsiste l'absence de StrongBox au banc.

### A4 — Capture et collecte

**Coupée en deux le 2026-08-12.** La liste d'origine mêlait deux difficultés
indépendantes : *assembler et signer une enveloppe*, que nul appareil n'a jamais
fait, et *collecter des données de capteurs*. Les traiter ensemble ferait payer la
première au prix des permissions et de l'appareil photo, alors qu'elle n'en a pas
besoin — et repousserait d'autant le critère de sortie du spike.

#### A4.1 — L'enveloppe, sans caméra

Profil **`core`** (ADR-0005) : ni position, ni dimensions, ni réclamations.
`media[2]` peut être l'empreinte de n'importe quels octets, le noyau n'affirmant
rien du monde physique. **Aucune permission, aucun appareil photo.**

Le cœur sait déjà tout faire : son encodeur CBOR et sa couche COSE reproduisent les
vecteurs d'or **octet à octet** depuis A2. Ce qui manque est l'assemblage sur
appareil.

- [x] **Câbler le vrai `PlayIntegrityVerifier` dans le serveur de dev.** Son
      `main()` construit toujours le substitut ; il lui faut le nom de paquet et le
      chemin du compte de service, deux valeurs de déploiement dont le `.env` est le
      logement (voir `.env.example`). Sans ce câblage, l'étape ne peut pas viser
      mieux que le substitut.
- [x] Point d'entrée `seal(bytes)` dans le cœur — `envelope/Sealer.kt`. Assemble et
      signe : empreinte des octets remis, collecte `timing`/`posture`, R1, jeton,
      `COSE_Sign1`. La fraîcheur passe par l'interface `FreshnessSource`, pour que
      l'assemblage ne dépende ni de Play Integrity ni de ce qui viendra.
- [x] Charge utile identique champ à champ à `factory.make_payload(profile="core")`
      — c'est l'oracle d'acceptation, et si le natif produit autre chose, c'est le
      natif qui s'écarte. **Épinglé par un test d'hôte** (`CorePayloadVectorTest`) :
      `CorePayload.build`, celui qu'appelle `Sealer`, reproduit `core.payload.cbor`
      octet à octet. Distinct de `GoldenVectorsTest`, qui bâtit sa charge utile à la
      main et n'éprouve donc que l'encodeur.
- [ ] Séquence sur appareil : nonce depuis `/nonce` → charge utile CBOR →
      R1 = `SHA-256(payload ‖ nonce)` → jeton Play Integrity sur ce R1 →
      `COSE_Sign1` signé par la clé Keystore enrôlée → `POST /verify`.
      **Exercée de bout en bout sur émulateur le 2026-08-13**, verdict rendu ;
      reste à la lancer sur SM-X200, seul appareil qui puisse cocher le critère
      de sortie — un émulateur n'a ni clé matérielle ni verdict d'appareil.

**Deux champs de `posture` sont omis, et l'omission est le comportement correct.**
L'indicateur de position simulée (label 7) ne se lit que sur un point de
localisation, qu'un scellement d'octets remis n'a pas ; la liste de paquets
suspects (label 8) suppose `QUERY_ALL_PACKAGES`, que l'acquisition paiera. Émettre
`false` et `[]` reviendrait à affirmer « j'ai regardé, il n'y a rien » — la
réclamation simulée qu'interdit la règle d'A6, et que le serveur ne pourrait pas
distinguer d'une vraie mesure. Les deux champs sont optionnels au CDDL : la charge
utile reste conforme.

**Ce que `media[6]` mesure ici, et ce qu'il ne mesure pas.** Le champ est *dans* ce
qui est encodé, donc il ne peut pas compter ce qui vient après lui — le jeton de
fraîcheur et la signature restent dehors. Pour des octets remis, l'instant d'origine
est l'entrée dans `seal`, ce qui est la seule chose honnête : le cœur ignore l'âge de
ce qu'on lui donne. `seal` prend malgré tout cet instant en paramètre, parce que
l'acquisition y passera celui de l'obturateur — c'est là seulement que le champ
discrimine une injection.

**Forme validée sur l'hôte avant campagne.** Une charge utile de cette forme exacte
— posture sans 7 ni 8, `text/plain`, sans chaînage — passe le pipeline : `STANDARD`,
`integrity` A, `origin` A, `time` **B** avec le drapeau `CHAIN_ABSENT`. Le B est
attendu et non un défaut : `time` n'atteint A que par ordonnancement vérifié, donc
par chaînage côté Android (A6), et une première enveloppe n'a par construction pas
de précédente.

**Critère de sortie d'A4.1, et il dépasse ce que la phase A demandait.** Le plan
prévoyait une enveloppe acceptée « avec substitut d'attestation ». La phase B étant
close, on peut l'obtenir **sans substitut** — donc atteindre le critère de sortie du
spike, jamais atteint sur aucune plateforme à ce jour.

**Commandes de la campagne.** Le `.env` doit porter `PROBATIVE_ANDROID_PACKAGE` et
`PROBATIVE_SERVICE_ACCOUNT`, sans quoi le serveur annonce au démarrage qu'il tombe
sur le substitut — et une campagne qui croirait valider une attestation réelle sans
en valider aucune serait le pire des résultats. **Lancer le serveur depuis la racine
du dépôt** : les chemins du `.env` y sont relatifs, et depuis `verifier-python/` le
fichier n'est simplement pas trouvé — le repli est alors annoncé, mais il faut le
lire.

```bash
python -m probative.devserver --port 8765   # à la RACINE du dépôt
adb reverse tcp:8765 tcp:8765

cd mobile/android
ANDROID_HOME=$HOME/Library/Android/sdk ./gradlew :demo:installDebug \
  -Pprobative.cloudProjectNumber=487335590129
adb logcat -c
adb shell am start -n org.probative.demo/.MainActivity
adb logcat -d -s PROBATIVE_A41
```

#### A4.2 — La collecte

- [ ] CameraX `ImageCapture` : octets JPEG bruts du capteur, SHA-256, type MIME,
      taille, dimensions — l'empreinte est calculée sur les octets qui partiront au
      serveur, sans ré-encodage intermédiaire. **Piège :** décoder en `Bitmap` puis
      ré-encoder change les octets ; le serveur rejetterait en
      `MEDIA_DIGEST_MISMATCH` sans que la cause soit lisible. On hache le tampon tel
      quel, et on envoie ce même tampon.
- [ ] `timing` : horloge murale, `elapsedRealtime`, décalage UTC, synchronisation
      automatique de l'heure.
- [ ] `position` : fused provider, précision, ancienneté du point **au
      déclenchement** (`position.7`), nombre de satellites si disponible. C'est un
      âge, pas un horodatage : il faut donc garder l'instant du point *et* celui de
      l'obturateur.
- [ ] `posture` : débogueur, émulateur suspecté, mode développeur, indicateur de
      position simulée, paquets suspects. **Déclaratif, donc faible** — le client
      collecte, le serveur juge (invariant 1) : aucune de ces valeurs ne conditionne
      quoi que ce soit sur l'appareil.
- [ ] Capteur absent → réclamation **omise, jamais simulée** (règle d'A6, facile à
      trahir avec une valeur par défaut).
- [ ] **Corroboration lancée *pendant* l'acquisition, jamais après.** Acquis de
      C4.2, et c'est la seule case dont l'oubli produit un verdict *plausible et
      faux* : collectée en aval de l'obturateur, elle entre dans `media[6]` et
      fait accuser une latence anormale là où il n'y en a aucune. Mesuré à
      +4,2 s sur iPhone 16.
- [ ] **Attendre un point de position frais**, plutôt qu'accepter le premier —
      qui est celui du cache. Mesuré à 42,9 s d'âge sur iPhone 16, quand un
      point frais arrivait une seconde plus tard. Attendre n'est pas filtrer :
      à l'expiration, on transmet le meilleur point obtenu **avec son âge réel**
      et c'est le serveur qui juge (invariant 1).

##### `baro-alt` sur Android — un faux positif intégré, à traiter avant la campagne

**Android n'expose aucune altitude absolue.** Là où iOS a
`startAbsoluteAltitudeUpdates`, Android n'a que `TYPE_PRESSURE` : il faut
*dériver* l'altitude, ce qui exige une pression de référence au niveau de la
mer. Et c'est là que ça casse.

Près du sol, la pression varie d'environ **1 hPa tous les 8,3 m**. La pression
au niveau de la mer, elle, oscille en pratique entre 980 et 1040 hPa selon la
météo. Utiliser la valeur standard de 1013,25 hPa alors que la réelle vaut
1030 donne donc :

      (1030 − 1013,25) × 8,3 ≈ 139 m d'erreur

soit **plus du double de la tolérance de 60 m**. Conséquence directe : par
temps de haute ou de basse pression, **un appareil Android parfaitement
honnête serait marqué « incohérence altimétrique » et `position` plafonnée à
C**. Le faux positif est intégré, il dépend de la météo du jour, et il
tomberait en pleine campagne sans que rien n'en désigne la cause.

- [ ] Trancher avant d'écrire la collecte. Trois issues, par ordre de
      préférence croissante :
      1. **élargir la tolérance pour Android** — affaiblit le contrôle partout,
         y compris là où il fonctionne ;
      2. **omettre `baro-alt` et n'envoyer que `baro`**, la pression brute, qui
         est une vraie mesure. Honnête et sans faux positif, mais Android perd
         la corroboration ;
      3. **envoyer la pression brute et laisser le serveur comparer**, en
         allant chercher lui-même la pression de référence pour le lieu et
         l'instant déclarés. C'est l'invariant 1 appliqué à la lettre — le
         client mesure, le serveur juge — et cela **renforce** la parade au
         lieu de l'affaiblir : le client ne connaît plus la valeur attendue,
         donc ne peut plus fabriquer une paire cohérente. C'est ce qui ferait
         passer la corroboration de « déclarée » à « vérifiée », et donc valoir
         contre l'injection, ce qu'elle ne fait pas aujourd'hui (§S1).

      La troisième a un coût réel : une source météo côté serveur. Le
      vérificateur appelle déjà Google pour Play Integrity, donc ce n'est pas
      un tabou — mais cela mérite un ADR, pas une décision en passant.

##### Préambule d'autorisations — à faire dès le début, pas à la fin

Acquis de C4.2, où l'oubli a coûté plusieurs campagnes. **Demander une
autorisation au moment où son capteur sert affiche la boîte de dialogue
*pendant* que le délai d'attente court** : le relevé expire, et le symptôme
n'accuse jamais la bonne cause — on soupçonne le GPS, le baromètre ou le
serveur, jamais la permission.

- [ ] Toutes les autorisations demandées **avant** la première mesure, avec
      leur état affiché à l'écran **et journalisé** : un extrait de logcat doit
      permettre de distinguer un capteur muet d'une autorisation manquante.
- [ ] La sonde ne démarre que si elle peut aboutir — partir sans caméra ni
      position produit un échec qui n'apprend rien.
- [ ] **Éprouvé à froid** : désinstaller puis réinstaller, ce qui remet les
      autorisations à zéro, et vérifier que la campagne passe **du premier
      coup**. C'est le seul test qui compte, et le seul qui ait trouvé quelque
      chose côté iOS.

**Quatre asymétries avec iOS, à ne pas transposer mécaniquement.**

| | Android | iOS |
|---|---|---|
| Demandes groupées | **Oui** — `requestPermissions` en accepte plusieurs | Non : une boîte à la fois, les demandes concurrentes sont jetées |
| Réseau local | **Aucune autorisation** : `adb reverse` et `usesCleartextTraffic` suffisent | Autorisation sans interface d'état, dont la première tentative échoue |
| Baromètre, accéléromètre | **Aucune autorisation** | « Mouvement et forme », sollicitée en démarrant un relevé |
| Podomètre | `ACTIVITY_RECOGNITION` depuis l'API 29 | Même autorisation que le baromètre |

Android a donc **deux pièges de moins** — pas de réseau local, pas
d'autorisation pour les capteurs de corroboration hors podomètre — mais un que
iOS n'a pas : le refus définitif. Deux refus valent « ne plus demander », et
`shouldShowRequestPermissionRationale` est le seul moyen de distinguer « pas
encore demandé » de « refusé pour de bon ». Les confondre fait proposer un
bouton qui ne peut rien.

**Deux points d'entrée, pas un.** L'acquisition par le cœur ne doit pas devenir le
seul chemin : un intégrateur qui possède déjà son écran photo doit pouvoir sceller
des octets qu'il fournit. Les deux existent, et ils ne produisent pas le même
profil (spec §2.5, « contenu acquis, contenu fourni ») :

- `capture()` — le cœur pilote la caméra, profil `capture` ;
- `seal(bytes)` — le cœur scelle des octets remis, profil `core`.

Le second n'est pas un mode dégradé mais une preuve **plus étroite**, et elle est
honnête : ni `position`, ni `media[6]` exploitable, ni plafond de recapture, parce
que rien n'est affirmé du monde physique. Le construire dès A4.1 coûte peu — c'est
exactement ce que fait l'étape, une enveloppe `core` sur des octets quelconques — et
l'omettre obligerait tout intégrateur à passer par la caméra du cœur ou à renoncer.

### A5 — Fraîcheur Play Integrity (règle R1)

- [x] Intégration API standard (`StandardIntegrityManager`) — `core/freshness/
      PlayIntegrity.kt`, exercée sur SM-X200 le 2026-08-11. Le type
      `StandardIntegrityTokenProvider` de Play est encapsulé dans une classe
      opaque : la surface publique du cœur ne doit pas faire fuir un type
      propriétaire, sans quoi les liaisons Flutter et React Native devraient
      embarquer Play Integrity rien que pour le nommer.
- [x] **Préchauffage confirmé nécessaire, chiffres à l'appui** : `prepare` coûte
      **1 313 ms à froid** et **533 ms à chaud**, quand la demande de jeton ne
      coûte que **36–39 ms**. Préparer le fournisseur au démarrage, jamais sur le
      chemin capture→signature.
- [x] `requestHash` = **base64url sans bourrage**, 43 caractères pour un plafond
      documenté à 500 — **inconnue n° 1 levée sur la taille** : le condensat de
      32 octets passe tel quel, aucun niveau d'indirection n'est nécessaire, la
      spec §3/R1 n'a pas à être révisée sur ce point.
- [x] **Aller-retour confirmé le 2026-08-12 — l'inconnue n° 1 est close.** Jeton réel
      de la SM-X200 déchiffré par `decodeIntegrityToken` (HTTP 200) : Play restitue
      `hO8pCZOl0-5UZs4k9CwIDGDlyzAp0bThKassj5XEabU`, soit **exactement** le R1
      recalculé côté hôte depuis la charge utile et le nonce de la sonde. Contrôle
      fait **par recalcul**, jamais en comparant deux chaînes produites par
      l'appareil. L'encodage ne diverge pas entre client et serveur : R1 ne casse pas
      en silence, ce qui était le pire mode de défaillance envisagé.
- [ ] Rendre l'encodage normatif dans ADR-0002 — plus rien ne le bloque.
- [ ] ~~Jeton opaque dans `freshness[2]`, enveloppe complète signée, acceptée par le
      serveur de dev avec substitut d'attestation.~~ **Déplacée en A4.1** le
      2026-08-12 : c'est le même travail, et le regrouper là évite de le croire fait
      parce qu'A5 est par ailleurs close. Visée revue à la hausse au passage — sans
      substitut, la phase B le permet désormais.

### A6 — Chaînage et corroboration

- [ ] `payload[7]` : SHA-256 de l'enveloppe précédente, persisté localement ;
      comportement à la première capture et après réinstallation documenté.
- [ ] Réclamations : `baro`, `baro-alt`, `motion` (fenêtre 10 s), `steps`,
      `activity`. Capteur absent → réclamation omise, jamais simulée.

### A7 — Mesures (inconnue n° 2)

- [ ] Protocole de mesure de `media.6` : n captures par appareil, distribution
      conservée (médiane, p95), pas seulement une moyenne.
- [ ] Mesure sur un appareil d'entrée de gamme et un milieu de gamme.
- [ ] Reporter les distributions ici et calibrer les constantes de `grading.py`.

**A7 fait plus que calibrer : elle tranche une décision de format.** La spec §9
laisse ouverte la question d'une attestation de clé **par capture**, qui rendrait
`RootOfTrust` vivant et donnerait à Android la vérification hors ligne qu'iOS a
déjà. Deux coûts s'y opposent — 3 413 octets de chaîne contre 629 pour une
enveloppe, et 38 ms de génération de clé à chaud. Si la latence de capture écrase
ces 38 ms, l'argument de coût s'affaiblit ; sinon il tient. **Aucun raisonnement ne
remplacera ce chiffre**, et c'est A7 qui le produit.

**Sortie de phase A :** le `:demo` produit sur appareil réel une enveloppe acceptée
par le serveur de dev (substitut d'attestation) ; AAR autonome ; latences mesurées.

---

## Phase B — `PlayIntegrityVerifier` serveur

- [x] Trancher le mode de déchiffrement du jeton : ~~API Play Developer (Google
      déchiffre) ou clés locales~~ — **tranché par contrainte le 2026-08-12, ce
      n'était pas un choix.** Le déchiffrement local exige que l'application soit
      disponible sur Google Play ; la nôtre ne l'est pas, et c'est précisément ce
      qu'A5 a établi comme chemin pris en charge. Donc : **appel à Google par
      enveloppe**, avec quatre conséquences à assumer (latence dans le chemin de
      vérification, dépendance de disponibilité, plafond de 10 000 requêtes/jour
      non négociable hors Play Store, argument d'auto-hébergement entamé côté
      Android). Procédure et sources : `play-integrity-service-account.md`.
- [x] **Authentification auprès de Google : couture injectable** (ADR-0006).
      `AccessTokenProvider` est un `Protocol` ; `ServiceAccountKeyProvider` en est
      l'implémentation par défaut, flux JWT-bearer signé maison, **zéro dépendance
      nouvelle** — le vérificateur reste à `cbor2` + `cryptography`. Un déploiement
      Google Cloud injecte `google-auth` et sa fédération d'identité. Éprouvé contre
      l'API réelle le 2026-08-12 dans le venv du projet : jeton réel déchiffré en
      HTTP 200, R1 confronté par recalcul.
- [x] Implémenter `attestation/play_integrity.py` : déchiffrement par
      `decodeIntegrityToken`, `requestHash` **recalculé** côté serveur et confronté au
      jeton, contrôle du nom de paquet, traduction des verdicts vers
      `AttestationOutcome`. 21 tests hors ligne, sur des réponses calquées sur la
      réponse réelle du 2026-08-12.

      Trois décisions inscrites dans le code plutôt que dans un commentaire de
      passage : un `deviceRecognitionVerdict` **vide** est un échec explicite et non
      un inconnu ; `MEETS_BASIC_INTEGRITY` seul est traité comme un échec, car il
      n'atteste pas un système non modifié ; et **Google injoignable rend
      `UNAVAILABLE`, jamais `FAILED`** — confondre panne et compromission
      déclarerait tout un parc fautif le jour d'une panne Google.
- [ ] Tests avec jetons réels capturés en phase A — **jamais versionnés**
      (`.gitignore`), chargés depuis un chemin local.
- [ ] Tests d'attaque référencés au modèle de menace (`test_s*_`) : jeton rejoué,
      jeton d'une autre application, `requestHash` d'une autre charge utile.
- [x] **Validation de la chaîne d'attestation de clé jusqu'à la racine Google.**
      `attestation/key_attestation.py`, éprouvé contre le vecteur SM-X200 réel.
      14 tests, dont celui qui compte : une chaîne **forgée de bout en bout** —
      racine auto-signée au même sujet, feuille portant le bon défi — est refusée
      par le seul ancrage. C'est la différence entre « la chaîne se tient » et
      « la chaîne est ancrée ».

      **Piège majeur trouvé à cette occasion :** l'ancrage doit porter sur la
      **clé publique**, jamais sur l'identité du certificat. Google a réémis sa
      racine RSA en 2022 en conservant la clé — la SM-X200 porte la série
      `d50ff25ba3f2d6b3` (2019-2034) quand Google publie `f1c172a699eaf51d`
      (2022-2042). Un ancrage par empreinte aurait rejeté une chaîne légitime, et
      le défaut ne se serait vu que sur du matériel ancien, donc tard.

      Les **deux** racines publiées sont versionnées, dont la EC P-384 « Key
      Attestation CA1 » effective depuis février 2026 : un appareil récent y
      chaînera.
- [x] **Câblée sur la route d'enrôlement** (`attestation_chain_b64`), et
      `DeviceRecord.hardware_backed` renseigné depuis l'attestation. Deux points
      qui ne vont pas de soi :

      - **La chaîne doit porter sur la clé qu'on enrôle.** Une attestation valide
        ne prouve rien tant que ce lien n'est pas établi : sans lui, une chaîne
        authentique obtenue pour une autre clé ferait enrôler n'importe laquelle.
      - **L'attestation prime sur le drapeau déclaré par le client.** Le
        `hardware_backed` du corps ne subsiste que pour le mode dégradé, celui où
        aucune chaîne n'accompagne l'enrôlement. Un client qui ment sur son
        matériel n'est pas cru dès lors qu'une chaîne est fournie.
- [ ] Réviser ADR-0002 : encodage normatif du `requestHash` (inconnue n° 1).

**Sortie de phase B : atteinte le 2026-08-12.** Boucle Android complète au vert
**sans** substitut, sur matériel réel — chaîne d'attestation ancrée à la racine
Google à l'enrôlement, jeton Play Integrity déchiffré et `requestHash` confronté
au R1 recalculé. *Reste hors périmètre de la phase :* réviser ADR-0002 pour rendre
l'encodage normatif, et faire signer une enveloppe complète — c'est A4.

---

## Phase C — Cœur iOS (`mobile/ios/`)

Package SwiftPM produisant un XCFramework, plus une application de démonstration.

### C1 — Squelette

- [x] `Package.swift` (iOS 15+, macOS 12 déclaré pour exécuter les tests sur
      l'hôte), cible bibliothèque sans dépendance framework. Le script
      `scripts/make_xcframework.sh` est validé de bout en bout (712 Ko, tranches
      appareil et simulateur, `.swiftinterface` embarquées). Recette notable :
      l'archivage xcodebuild d'un package SwiftPM ne produit aucun framework —
      on assemble `.o` → `libtool` → `-create-xcframework`, le swiftmodule posé
      à côté de la `.a` étant embarqué automatiquement. L'application de
      démonstration est différée à C4, comme `:demo` côté Android.

### C2 — Encodeur CBOR canonique + COSE_Sign1 en Swift

- [x] Mêmes exigences qu'en A2, validé contre les **mêmes vecteurs d'or** :
      13 tests au vert du premier coup. Modèle `CborValue` typé (maps à clés
      entières figées dans le type), demi-précision portable par manipulation de
      bits, conversion DER → `r‖s` croisée avec CryptoKit (`derRepresentation`
      contre `rawRepresentation` d'une même signature).

### C3 — Clé et enrôlement App Attest

- [x] `DCAppAttestService.generateKey()` et attestation initiale, **obtenues sur
      iPhone 16 réel** (iOS 26.6) via l'application de démonstration
      `mobile/ios/demo`. Objet de 5 816 octets, `fmt = apple-appattest`, chaîne
      `x5c` à 2 certificats, reçu de 3 966 octets. Deux liaisons vérifiées par
      recalcul, pas par lecture : `rpIdHash == SHA-256("9SGKL7VUD3.org.probative.demo")`
      et `credentialId == keyId`. `aaguid = appattestdevelop` — environnement de
      développement, ce que la phase D devra accepter explicitement.
- [ ] Transmission à `POST /enroll` — reportée avec la phase D : le serveur ne
      sait pas encore valider une attestation Apple, l'y envoyer ne prouverait
      rien. Le vecteur capturé est ce qui permet d'écrire cette validation.
- [x] Clé de signature d'enveloppe Secure Enclave, export public X9.62, même `kid`
      que la convention Android — **validé sur l'enclave réelle du Mac hôte**
      (Apple Silicon, même API que l'appareil) : création, export, signature
      vérifiée par CryptoKit ; convention kid confirmée contre le manifest des
      vecteurs, aller-retour Security exact.

### C4 — Capture et collecte

**Coupée en deux le 2026-08-13**, comme A4 et pour la même raison : assembler une
enveloppe et collecter des capteurs sont deux difficultés indépendantes.

#### C4.1 — L'enveloppe, sans caméra — **FAITE, critère de sortie du spike atteint**

- [x] Cœur Swift : `Payload.swift` (construction pure), `DeviceState.swift`
      (collecte `timing`/`posture`, aucune autorisation), `Sealer.swift` et le
      protocole `FreshnessSource`. Pendants exacts des fichiers Kotlin.
- [x] **Quatrième vecteur d'or, `core-ios`.** Il manquait : le jeu `core` est de
      forme Android (posture 6/7/8), et le cœur Swift produit une posture iOS
      (label 9). Rien ne pouvait donc l'épingler. `posture` est le **seul** bloc
      dont la forme dépende de la plateforme, donc le seul endroit où un cœur
      peut produire une charge utile valide qu'aucun vecteur ne couvre.
- [x] **Câbler App Attest dans le serveur de dev** — `PROBATIVE_APPLE_TEAM_ID`,
      `PROBATIVE_IOS_BUNDLE_ID`, `PROBATIVE_APPATTEST_ENV`. La même configuration
      sert deux fois : valider l'attestation d'enrôlement et valider l'assertion
      de chaque enveloppe.
- [x] **Aiguillage par plateforme.** `PlayIntegrityVerifier` et
      `AppAttestVerifier` lèvent chacun sur la plateforme de l'autre — à raison —
      et le serveur n'en câblait qu'un. Une plateforme non configurée fait lever,
      jamais rendre un verdict défavorable : « non jugé » et « jugé mauvais »
      n'appellent pas la même conduite.
- [x] Séquence sur appareil : **exécutée sur iPhone 16 (iOS 26.6) le 2026-08-13**,
      verdict `STRONG`, trois propriétés au grade A, aucun drapeau.

#### C4.2 — La collecte — **FAITE le 2026-08-13, iPhone 16**

- [x] AVFoundation : octets JPEG bruts, empreinte, dimensions ; `timing`,
      `position` (CoreLocation + ancienneté), `posture` iOS (`posture[9]`).
- [x] Corroboration : `baro`/`baro-alt` (CMAltimeter), `motion`, `steps`.
      ~~`activity`~~ non collectée : `CMMotionActivity` demande une
      autorisation de plus pour un signal qu'aucune règle de notation ne lit.
- [x] `CapturePayload` épinglé au vecteur d'or `ios` **octet à octet** — le
      seul jeu portant les quatre réclamations et une position sans nombre de
      satellites, donc le seul oracle du profil `capture` côté iOS.

**Verdict obtenu : `STANDARD`, et c'est le maximum atteignable en v0.1.**

      integrity   A   cose-valid, key-attested-hardware, app-attest:*
      origin      B   plafond de recapture — ADR-0005
      position    A   gnss, baro-consistent, motion-present
      time        A   assertion-counter-monotonic
      drapeaux        aucun

`origin` à B n'est pas un défaut : c'est l'angle mort assumé de la v0.1, et
le seul motif de `level_reason`. Les trois autres propriétés sont au grade A.

**Mesures — l'inconnue n° 2 est levée.** Capture AVFoundation **1 904 ms**
(dont 400 ms d'attente de convergence délibérée), scellement **49 ms**,
enveloppe **734 octets**, vérification **280 ms**. La capture domine tout le
reste de deux ordres de grandeur ; la fraîcheur, qu'on soupçonnait, ne coûte
rien. Le seuil de `max_sign_latency_ms` (3 000 ms) tient — mais avec une
marge bien plus faible qu'on ne l'imaginait, et c'est ce qui rend les trois
pièges ci-dessous décisifs plutôt qu'anecdotiques.

**Trois pièges, tous mesurés, aucun devinable.**

1. **La corroboration doit courir *pendant* l'acquisition, jamais après.**
   Collectée en aval de l'obturateur, elle ajoutait **4,2 s** à `media[6]` :
   `origin` tombait à C pour « latence payload→signature anormale », alors
   que rien d'anormal ne s'était produit. Le champ censé discriminer une
   injection n'accusait que l'ordonnancement du client. Les mesures encadrent
   la capture, elles ne la suivent pas — ce qui est aussi la lecture juste du
   format : une corroboration décrit l'instant de la prise.
2. **Le premier point que rend CoreLocation est celui du cache.** Mesuré à
   **42 922 ms** d'âge, il faisait tomber `position` à C pour « point vieux au
   déclenchement » quand un point frais arrivait une seconde plus tard.
   `Sensors.location` attend donc un point sous un âge plafond — **attendre
   n'est pas filtrer** : à l'expiration, le point le plus frais obtenu est
   rendu *avec son âge réel*, et c'est le serveur qui juge (invariant 1).
3. **`CLLocationManager` exige un fil doté d'une boucle d'exécution.** Créé
   depuis un contexte `async` — donc sur la réserve coopérative, qui n'en a
   pas — il ne délivre **jamais** ses rappels : aucune erreur, aucun
   avertissement, juste un délai qui expire. On impute d'abord la panne au
   GPS ; elle est dans le fil d'exécution.

**Deux conventions d'unité, que le format ne fixe pas.** `baro-alt` est en
**mètres**, pour être confrontable à `position[4]` — c'est le vérificateur qui
l'impose. `baro` est en **hectopascals**, l'unité que rend nativement Android
(`Sensor.TYPE_PRESSURE`) ; iOS donne des kilopascals et convertit. Sans cette
convention, deux plateformes rapporteraient la même mesure à un facteur dix
près et **rien dans le format ne le dirait**. À rendre normatif dans la spec.

**Deux relevés supposent l'autorisation de mouvement**, qui est demandée à la
première lecture du baromètre. Tant qu'elle n'est pas accordée, `baro-alt` et
`baro` sont **omis** — jamais simulés — et `position` perd `baro-consistent`
sans pour autant échouer.

**Ce que l'altitude barométrique n'est pas.** `startRelativeAltitudeUpdates`
ne rend qu'un *écart* depuis le début des relevés ; la confronter à l'altitude
GNSS n'a aucun sens et le vérificateur crierait à l'incohérence altimétrique
sur un appareil sain. C'est `startAbsoluteAltitudeUpdates` qu'il faut — et
c'est la seconde API qu'on rencontre, pas la première.

**Trois différences avec Android, toutes structurelles.**

- **Il n'existe pas d'`adb reverse` sur iOS.** L'appareil ne voit pas la boucle
  locale du Mac, même relié en USB. Le serveur doit écouter sur le réseau local
  (`--host 0.0.0.0`) et les deux machines partager le Wi-Fi. D'où deux clés dans
  l'`Info.plist` : `NSAppTransportSecurity/NSAllowsLocalNetworking` — préférée à
  `NSAllowsArbitraryLoads`, qui lèverait tout — et
  `NSLocalNetworkUsageDescription`, sans laquelle la connexion échoue en
  `-1009`, « The Internet connection appears to be offline ». **Le message ne dit
  pas que la permission manque**, et la première exécution échoue toujours : la
  boîte de dialogue s'affiche pendant que la requête part.
- **`timing[4]` est toujours omis.** iOS n'expose aucune interface publique
  disant si l'heure est réglée automatiquement, là où Android a
  `Settings.Global.AUTO_TIME`. Le label est optionnel : l'asymétrie est absorbée
  par le format, ce qui est exactement l'invariant 4 à l'œuvre.
- **`time` atteint A sans rien faire**, par `assertion-counter-monotonic`. Le
  compteur signé dans `authenticatorData` fait foi ; le compteur de l'en-tête de
  fraîcheur n'est signé par rien, et il est donc **omis** — le déclarer
  n'apporterait rien et un désaccord serait un rejet. Android doit gagner le même
  grade par chaînage (A6).

### C5 — Fraîcheur (règle R1)

- [x] `generateAssertion(clientDataHash: R1)` — **exercé sur appareil réel** avec
      un R1 calculé pour de bon, `SHA-256(payload_bytes ‖ nonce)` : assertion de
      142 octets, signature DER de 72 octets, compteur passé de 0 à 1. Les 32
      octets bruts passent sans encapsulation, l'inconnue d'encodage qui pesait
      sur Android (`requestHash`) n'a pas d'équivalent ici. La charge utile reste
      synthétique : le branchement sur une capture réelle est en C4.
- [ ] Pas de chaînage `payload[7]` : le compteur joue ce rôle (spec §2.3).
- [ ] Mesure de `media.6` sur un appareil iOS réel, reportée ici.

**Sortie de phase C :** enveloppe iOS acceptée par le serveur de dev (substitut) ;
XCFramework autonome.

---

## Phase D — `AppAttestVerifier` serveur

- [x] `attestation/app_attest.py` : chaîne x5c validée **jusqu'à la racine publiée
      par Apple**, versionnée dans `attestation/roots/`. Défi d'enrôlement retrouvé
      dans l'extension `1.2.840.113635.100.8.2`, `keyId`, `rpIdHash`, compteur
      initial à zéro et `aaguid` contrôlés. Vérification des assertions à la
      capture. Éprouvé contre le vecteur iPhone 16 réel.
- [x] Compteur strictement croissant (étape 6). **Correction apportée au passage :**
      le compteur de l'en-tête de fraîcheur n'est signé par rien ; celui
      d'`authenticatorData` l'est. Seul le second fait foi, un désaccord est un rejet.
- [x] Tests d'attaque : racine contrefaite au même sujet, défi d'enrôlement étranger,
      autre application, autre équipe, environnement de production contre clé de
      développement, certificat expiré, algorithme de signature hostile, compteur
      déclaré ≠ compteur signé, `clientDataHash` d'une autre charge utile.
- [ ] **Assertion rejouée** : couverte indirectement par R3 au niveau de l'enveloppe,
      pas par un test dédié au niveau de l'assertion.
- [ ] **Reçu App Attest** conservé mais non validé — sa vérification exige un appel
      à Apple, hors périmètre retenu.
- [ ] **Révocation** : Apple publie une liste pour App Attest, non consultée. La
      durée de vie de trois jours du certificat feuille en limite fortement l'enjeu.

**Sortie de phase D — atteinte à une réserve près, qui n'est pas mince.** Attestation
et assertion sont validées **isolément**, jamais une enveloppe complète de bout en
bout : la sonde C3 a signé une charge utile de substitution et non un `COSE_Sign1`,
donc le pipeline ne peut pas rejouer ce vecteur. Ce n'est donc **pas** la fin du
spike : il y faut une itération de C3, ou C4.

---

## Clôture du spike

- [ ] Geler la spec d'enveloppe (statut « proposition » → gelée), y intégrer
      l'encodage R1 normatif.
- [ ] Trancher le chaînage Android (spec §9) — ADR si la chaîne locale ne suffit
      pas.
- [ ] Constantes de `grading.py` recalibrées sur les latences mesurées (A7, C5).
- [ ] Mettre à jour CLAUDE.md et README (état des composants, prochaine étape :
      liaisons `bindings/`, ADR-0003).
- [ ] Archiver ce document : les décisions en ADR, les mesures en annexe.

---

## Prérequis logistiques — à fournir, hors code

- [x] ~~Application déclarée dans la Play Console (piste interne suffisante)~~ —
      **non requise, établi le 2026-08-12 par un jeton réel déchiffré en HTTP 200.**
      Google résout l'application depuis le jeton, qui porte le lien vers le projet
      Cloud, et non depuis le nom de paquet de l'URL. Ni délivrance ni déchiffrement
      n'exigent la Play Console. *Un refus obtenu avec un jeton volontairement
      invalide avait fait conclure l'inverse quelques heures plus tôt : voir
      `play-integrity-service-account.md` §7, la leçon de méthode y est consignée.*
- [x] Projet Google Cloud lié pour l'API standard Play Integrity. *(Projet
      `probative`, 487335590129 ; API activée, confirmé par appel réel.)*
- [x] **Compte de service** dans ce même projet Cloud, pour déchiffrer les jetons —
      `probative-verifier@probative.iam.gserviceaccount.com`, créé et **exercé contre
      l'API réelle le 2026-08-12** : jeton d'accès obtenu, aucun rôle IAM nécessaire.
      Procédure dans `play-integrity-service-account.md`.
- [ ] Appareil Android réel d'entrée de gamme + un milieu de gamme (émulateur non
      représentatif pour Play Integrity et StrongBox).
- [x] Compte développeur Apple payant. *(équipe `9SGKL7VUD3` ; le profil joker
      `9SGKL7VUD3.*` couvre `org.probative.demo` sans démarche sur le portail.)*
- [x] Appareil iOS réel (App Attest indisponible sur simulateur). *(iPhone 16,
      iOS 26.6.)*

## Journal

- 2026-08-06 : plan rédigé, phases 0/A/B/C/D définies. Rien de commencé.
- 2026-08-06 : **phase 0 terminée.** Vecteurs d'or (`tests/vectors/`, générateur
  `tools/gen_vectors.py`, signature RFC 6979) et serveur de dev
  (`probative.devserver`, socle stdlib au lieu de FastAPI — zéro dépendance
  nouvelle). 50 tests au vert. Trouvaille utile pour A2/C2 : les vecteurs
  contiennent du float16, du float32 et du float64 — la demi-précision CBOR est
  incontournable côté natif. Prochaine étape : phase A (squelette Gradle A1).
- 2026-08-06 : **A1 et A2 terminées.** `mobile/android/` : module `:core` (AAR
  autonome, 12 Ko), encodeur CBOR canonique et couche COSE en Kotlin pur, 13 tests
  au vert — les vecteurs d'or sont reproduits octet à octet du premier coup, demi-
  précision comprise. `:demo` différé à A4. Prochaine étape : A3 (clé Keystore et
  enrôlement), qui demande un appareil réel pour ses tests instrumentés.
- 2026-08-06 : **C1 et C2 terminées.** `mobile/ios/` : package SwiftPM
  `ProbativeCore`, encodeur CBOR canonique et couche COSE en Swift, 13 tests
  au vert contre les mêmes vecteurs d'or, XCFramework produit et validé par
  script (712 Ko). Les deux cœurs sont désormais au même point : tout ce qui se
  valide sans matériel est fait. Restent A3–A7 (appareil Android + Play Console)
  et C3–C5 (appareil iOS + compte développeur Apple).
- 2026-08-06 : **audit complet.** Les trois suites relancées d'un état propre
  (51 + 13 + 13, ruff et mypy au vert). Contre-épreuves cbor2 : les flottants
  limites (sous-normaux half, NaN, bornes float32) sont identiques entre cbor2,
  Kotlin, Swift et la RFC 8949 ; en revanche, divergence latente confirmée sur
  l'ordre des clés de map — cbor2 trie « longueur d'abord » (RFC 7049), les
  natifs « octets d'abord » (RFC 8949) ; les deux coïncident uniquement pour des
  clés non signées → contrainte rendue **normative** dans la spec §7. Corrigé :
  le serveur de dev fermait la connexion sur un corps non-UTF-8
  (`UnicodeDecodeError` non attrapée) ; durci : l'anti-dérive des vecteurs
  ignore les fichiers cachés. Vérifié : l'AAR ne dépend que de kotlin-stdlib
  (aucune dépendance framework), archive saine ; le pipeline rejette proprement
  un CBOR illisible via HTTP (`MALFORMED_ENVELOPE`, jamais de 500). Docs
  rafraîchies (51 tests, états des cœurs).
- 2026-08-06 : **A3 et C3 écrites à l'aveugle, validées autant que l'hôte le
  permet.** Android : `EcPublicKeys` (X9.62/kid, validé contre le manifest) et
  `KeystoreKeys` (StrongBox→TEE, attestation, signature DER→r‖s) ; tests
  instrumentés prêts, APK de test compilé — 15 tests unitaires au vert. iOS :
  `SigningKey` et `AppAttest` ; 17 tests dont la **Secure Enclave réelle du Mac
  hôte** (création, signature vérifiée par CryptoKit) — seul App Attest se
  saute hors appareil. XCFramework reconstruit (1,0 Mo). Le jour du matériel :
  `connectedDebugAndroidTest` côté Android ; côté iOS, App Attest attendra
  l'application de démonstration provisionnée (C4).
- 2026-08-06 : **second audit (A3/C3).** La reconstruction raw→DER du test
  instrumenté — code qui n'avait jamais tourné — est prouvée par réplique exacte
  en Python : 500 signatures + cas limites, octet à octet identique au DER
  canonique de `cryptography` ; le risque de brûler la première session
  d'appareil sur ce point est écarté. Trous de couverture comblés : persistance
  trousseau iOS testée (`load`/`delete`, aller-retour exact — 18 tests Swift),
  cas « coordonnée courte » rendu déterministe côté JVM, requête `load` filtrée
  sur `kSecAttrKeyClassPrivate`. À traiter en C4 : `create` sous une étiquette
  déjà occupée duplique l'entrée de trousseau — il faudra un
  « créer-si-absent ».
- 2026-08-11 : **A3 franchie sur matériel réel.** Samsung SM-X200 (Galaxy Tab A8
  Wi-Fi, Unisoc T618, Android 14) : `connectedDebugAndroidTest`, 3 tests, 0 échec
  et surtout **0 sauté** — le journal du serveur (`POST /enroll 200`) confirme que
  l'enrôlement s'est réellement produit et n'a pas été escamoté par `assumeTrue`.
  Le code écrit à l'aveugle passe au premier contact ; le double filet
  `StrongBoxUnavailableException` / `ProviderException` a servi, cet appareil
  n'ayant pas de StrongBox. Serveur rendu joignable par `adb reverse`, plus sobre
  que `--host 0.0.0.0`. Deux réserves consignées en A3 : le chemin StrongBox
  n'est pas exercé faute d'appareil, et la chaîne d'attestation reste non validée
  (phase B). Prochaine étape : **A4**, capture CameraX et collecte.
- 2026-08-11 : `docs/etat-de-l-art.md` — analyse des solutions voisines (Approov,
  Guardsquare, Truepic Lens, C2PA, ProofMode). Trois conséquences pour la suite :
  un article académique de 2026 montre que C2PA ne couvre pas son horodatage par
  la signature et laisse modifier les métadonnées GPS via ses zones d'exclusion,
  ce qui conforte l'ordre choisi (liaison dure d'abord, passerelle C2PA ensuite) ;
  le Pixel 10 signe désormais **toutes** ses photos nativement au niveau
  d'assurance 2, ce qui déplace notre valeur vers ce que le natif ne fait pas ; et
  Truepic paraît répondre à notre angle mort par l'empreinte de bruit de capteur,
  piste à instruire pour v0.3.
- 2026-08-11 : **projet renommé `attested-capture` → `probative`**, sur toute la
  surface cette fois. Au sens juridique, « qui tend à prouver » : une pièce a une
  valeur probante *appréciée par un tiers*, jamais autoproclamée — c'est exactement
  l'invariant n° 1. Suivent le paquet Python, le tag de format `probative/0.1`
  (label 100), l'extension `.prbv`, le type MIME `application/vnd.probative+cose`,
  la règle CDDL `probative-envelope`, le paquet Kotlin `org.probative.core`, le
  module Swift `ProbativeCore`, et les propriétés d'injection de test
  (`probative.vectors.dir`, `probative.devserver`).
- 2026-08-11 : **C3 franchie sur matériel réel** — iPhone 16, iOS 26.6, équipe
  `9SGKL7VUD3`. Première application de démonstration du dépôt
  (`mobile/ios/demo`, bundle `org.probative.demo`) : App Attest exige un App ID
  provisionné, qu'un bundle de test XCTest n'a pas, il fallait donc un hôte
  applicatif. Le projet Xcode n'est pas versionné — `scripts/make_demo_project.rb`
  le régénère, un pbxproj étant illisible en revue. La séquence complète passe du
  premier coup : `generateKey`, `attestKey`, `generateAssertion`, plus la clé
  d'enveloppe Secure Enclave, cette fois sur l'enclave de l'appareil et non celle
  du Mac hôte.

  Les deux liaisons qui comptent sont vérifiées **par recalcul** :
  `rpIdHash == SHA-256(teamId.bundleId)` et `credentialId == keyId`. Le compteur
  d'assertion démarre à 0 et passe à 1 — c'est l'état que la phase D devra
  persister dans `DeviceRecord`.

  **Latences mesurées** (à confronter à `grading.py` en clôture) : création de clé
  Secure Enclave 6,3 ms, signature 4,8 ms, **assertion 18 ms**, attestation
  d'enrôlement 1 230 ms. L'écart de deux ordres de grandeur est structurel :
  l'enrôlement fait un aller-retour chez Apple, l'assertion est locale. Bonne
  nouvelle pour l'inconnue n° 2 — la fraîcheur R1 ne coûte rien au chemin
  capture→signature ; c'est la capture elle-même qu'il faudra mesurer en C4.

  Réserve : l'environnement est `appattestdevelop`. Un build de distribution
  produira `appattestprod` et une racine différente ; la phase D doit traiter les
  deux, et un vecteur de développement ne prouve pas le chemin de production.
- 2026-08-11 : **vecteur d'appareil Android capturé**, rétablissant la symétrie
  avec iOS — les deux plateformes ont désormais une capture réelle versionnée.
  Contrôle décisif obtenu sur la SM-X200 : le défi que le TEE inscrit dans
  l'extension d'attestation vaut exactement le R1 recalculé côté hôte. La chaîne
  de 4 certificats s'enchaîne, chaque signature vérifiée, racine auto-signée, et
  la clé du certificat feuille est bien celle qu'exporte le cœur.

  À l'occasion, une asymétrie de rigueur a été corrigée : côté iOS, seule la
  cohérence *interne* de l'attestation avait été vérifiée — la signature d'Apple,
  jamais. Les deux vecteurs sont donc au même stade : cohérents avec eux-mêmes,
  sans ancre de confiance. C'est exactement ce que les phases B et D apportent, et
  la raison pour laquelle aucune des deux ne peut être déclarée faite.

  Point de méthode : le vecteur ressort par **logcat en tronçons numérotés**, pas
  par un fichier. Gradle désinstalle le paquet de test à la fin de la campagne —
  emportant son répertoire de données — et depuis Android 11 `adb` ne peut plus
  lire `Android/data` d'une autre application. Le tampon logcat survit aux deux.
- 2026-08-11 : **A5 largement franchie, inconnue n° 1 levée sur la taille.** Module
  `:demo` restauré depuis le tag `abandon/renommage-probative` — seul endroit où il
  subsistait — puis réécrit : le commit abandonné portait un état bien plus ancien
  du cœur. Sonde A5 exécutée sur SM-X200 avec le projet Cloud `probative`
  (487335590129).

  **Le jeton est délivré alors que l'application n'est *pas* déclarée dans la Play
  Console.** Contraire à nos attentes, mais **conforme à la documentation**, qui
  est explicite : le numéro de projet Cloud est *requis pour les applications
  distribuées exclusivement hors de Google Play*, et configuré dans la Play Console
  pour les autres. `setCloudProjectNumber` existe donc exactement pour ce cas —
  aucun contrôle n'est contourné. Le jugement se fait ailleurs : le jeton déchiffré
  porte `appRecognitionVerdict`, qui vaut ici très probablement
  `UNRECOGNIZED_VERSION`. Google délivre et laisse juger le serveur : le même
  partage que l'invariant n° 1.

  Deux conséquences. A5 a pu avancer sans ouvrir la Play Console. Et surtout, le
  chemin **hors Play étant officiellement pris en charge**, ce dépôt peut servir des
  applications distribuées en interne ou par sideload, pas seulement publiées sur le
  Store — ce qui compte pour une bibliothèque destinée à être réutilisée.

  **Mesures** (deux exécutions) : `prepare` 1 313 ms à froid puis 533 ms à chaud ;
  demande de jeton **36 puis 39 ms** ; jeton de 528–530 caractères ; génération de
  clé matérielle 264 ms à froid puis 61–70 ms. Le préchauffage du fournisseur, que
  le plan supposait utile, est confirmé nécessaire — deux ordres de grandeur entre
  `prepare` et la demande.

  Comparaison avec iOS, sur le seul chiffre qui compte pour `media.6` : fraîcheur
  **36–39 ms sur Android, 18 ms sur iPhone 16**. Le même ordre de grandeur, et
  négligeable devant une capture photo. L'inconnue n° 2 se joue donc bien dans la
  capture elle-même (A4/C4), pas dans l'attestation.

  Réserve : l'encodage du `requestHash` n'est validé **qu'en émission**. Tant que
  la phase B ne l'a pas relu dans un jeton déchiffré, rien ne prouve que Play le
  restitue intact — et un encodage qui diverge entre client et serveur casse R1
  silencieusement, ce qui est le pire mode de défaillance possible.
  Les vecteurs d'or ont dû être régénérés : l'en-tête protégé entre dans
  `Sig_structure`, donc changer le tag change aussi les signatures. C'est
  précisément le couplage que les vecteurs existent pour rendre visible — et les
  trois implémentations l'ont suivi sans retouche.
  Vérifié de bout en bout : Python 51 tests + ruff + mypy, Kotlin 30 tests unitaires,
  Swift 18 tests (1 sauté hors appareil), et **le test instrumenté rejoué sur la
  SM-X200 — 3 tests, 0 sauté, `POST /enroll 200`**. AAR toujours autonome
  (`kotlin-stdlib` seul), XCFramework reconstruit en `ProbativeCore.xcframework`.
  Espace de noms `org.probative` ; `probative.org` est libre, `probative.io` était
  déjà déposé par un tiers.

- 2026-08-13 : **A4.1 écrite, non encore exécutée sur appareil.** Le cœur Android
  sait désormais assembler et signer une enveloppe complète : `payload/Payload.kt`
  (construction pure, sans dépendance Android), `payload/DeviceState.kt` (collecte
  `timing`/`posture`, **aucune permission**), `freshness/FreshnessSource.kt`
  (l'assemblage ne connaît plus Play Integrity, seulement une interface) et
  `envelope/Sealer.kt`, qui est le point d'entrée `seal(bytes)` de la spec §2.5.

  Le contrôle qui compte est passé sur l'hôte : `CorePayload.build`, celui-là même
  qu'appelle `Sealer`, reproduit `core.payload.cbor` **octet à octet**. La
  différence avec `GoldenVectorsTest` n'est pas cosmétique — là-bas la charge utile
  est bâtie à la main dans le test, ce qui éprouve l'encodeur et non le code
  d'appareil. Un décalage entre les deux échouait jusqu'ici sur une SM-X200, sous
  la forme d'un `SIGNATURE_INVALID` sans cause visible.

  Deuxième dérisquage avant campagne : une charge utile de la forme exacte que
  produit `Sealer` — posture sans les labels 7 et 8, `text/plain`, sans chaînage —
  a été passée au pipeline. `STANDARD`, `integrity` A, `origin` A, `time` **B**,
  drapeau `CHAIN_ABSENT`. Le B est structurel : `time` n'atteint A que par
  ordonnancement vérifié, donc par chaînage sur Android, et une première enveloppe
  n'a pas de précédente. C'est A6, pas un défaut d'A4.1.

  Deux décisions valent d'être retenues, parce qu'elles se prendront à l'identique
  côté iOS :

  - **une mesure non faite s'omet, elle ne se simule pas.** Position simulée et
    paquets suspects sont absents de la posture, faute d'un point de localisation
    et de `QUERY_ALL_PACKAGES`. Émettre `false` et `[]` affirmerait « j'ai regardé,
    il n'y a rien », que le serveur ne saurait pas distinguer d'une vraie mesure ;
  - **`media[6]` ne peut pas mesurer ce qui vient après lui**, puisqu'il est dans
    ce qui est encodé. Jeton de fraîcheur et signature restent dehors. Pour des
    octets remis, l'instant d'origine est l'entrée dans `seal` — le cœur ignore
    l'âge de ce qu'on lui donne, et prétendre le contraire serait la première
    contre-vérité du format.

  La sonde `:demo` remplace A5, dont elle est un sur-ensemble strict. Reste la seule
  case qui compte : la lancer sur SM-X200. Aucun appareil branché à ce poste ce
  jour-là.

  Vérifié : Kotlin 17 tests unitaires au vert, `:demo:assembleDebug` compilé.

- 2026-08-13 : **A4.1 exercée de bout en bout sur émulateur.** Pixel_6a, image
  Google Play, Android 17 arm64. Ce n'est pas la campagne — un émulateur n'a ni clé
  matérielle ni verdict d'appareil — mais elle rapporte trois choses qu'on ne
  savait pas.

  **Le contrôle négatif de l'attestation de clé est passé pour de vrai.** Enrôlement
  refusé, `HTTP 400` : *« racine de la chaîne absente des racines publiées par
  Google : chaîne cohérente mais non ancrée »*. La chaîne était pourtant produite
  par un vrai Keystore et parfaitement cohérente — c'est exactement le cas que la
  phase B devait intercepter, et jusqu'ici seule une chaîne forgée en test l'avait
  vérifié.

  **R1 est vérifiée de bout en bout sur une enveloppe réellement assemblée par le
  cœur.** Le résultat porte `play-integrity:r1-bound` : le condensat a traversé
  l'encodage Kotlin, le `requestHash` base64url, les serveurs de Google, puis le
  recalcul Python depuis les octets reçus, sans dériver. L'inconnue n° 1 était close
  sur un jeton isolé ; elle l'est désormais sur le chemin complet, qui est le seul
  où une divergence d'encodage aurait cassé R1 en silence.

  **La boucle entière tient en moins d'une seconde.** Charge utile 131 octets,
  enveloppe **742 octets**, scellement **18–28 ms**, vérification **396 ms** — dont
  l'essentiel est l'aller-retour `decodeIntegrityToken` chez Google, coût structurel
  du mode de déchiffrement tranché en phase B. `prepare` : 1 365 ms à froid, 153 ms
  à chaud, cohérent avec les 1 313 / 533 ms de la SM-X200.

  Verdict `UNTRUSTED`, et c'est la bonne réponse : `origin` **F** — binaire installé
  par `adb`, donc signé par la clé de débogage et non par le certificat de
  déploiement Play — et *« réponse sans verdict d'appareil : Google n'atteste pas
  cet appareil »*, ce qu'un émulateur mérite. `integrity` C, `time` B,
  `CHAIN_ABSENT`.

  **Mode répétition, ajouté pour ceci** (`-Pprobative.rehearsal=true`, jamais par
  défaut, bannière en tête de sonde) : la clé est enrôlée sur parole, faute de
  pouvoir l'attester. Premier jet **flatteur et donc faux** — le serveur suppose
  `hardware_backed` vrai quand le client ne dit rien, si bien qu'une clé logicielle
  d'émulateur ressortait `key-attested-hardware` et hissait `integrity` en **A**. Le
  démenti est désormais explicite, et la note retombe à **C**. Une répétition qui
  flatte le résultat est pire qu'une répétition qui échoue.

  Piège de parcours, noté dans les commandes : le serveur doit être lancé **depuis
  la racine du dépôt**, les chemins du `.env` y étant relatifs. Depuis
  `verifier-python/`, il tombe sur le substitut — en l'annonçant, mais l'annonce se
  perd si la sortie est redirigée sans `python -u`.

  Défaut d'affichage trouvé en regardant l'écran, et non le journal : la version
  du binaire n'apparaissait pas. Premier diagnostic — le `TextView` sélectionnable
  prend le focus et le `ScrollView` défile pour le suivre — **faux**. La cause est
  le **bord à bord imposé depuis `targetSdk 35`** : la fenêtre occupe l'écran
  entier et les premières lignes se dessinaient sous la barre système. Corrigé par
  un recul aux insets, et l'identité est désormais épinglée hors de la zone
  défilante. Ce n'est pas cosmétique : lire un verdict sans savoir quel binaire
  l'a produit est précisément ce qu'A5 avait signalé.

- 2026-08-13 : **CRITÈRE DE SORTIE DU SPIKE ATTEINT — iPhone 16, iOS 26.6.**
  Pour la première fois sur une plateforme quelconque, un appareil réel a produit
  une enveloppe `probative/0.1` que le vérificateur a acceptée, **avec validation
  d'attestation réelle** et non le substitut :

      niveau           STRONG
      motif            toutes les propriétés au grade A
      integrity   A    cose-valid, key-attested-hardware,
                       app-attest:assertion-valid, app-attest:r1-bound
      origin      A    raw-hash-match, app-recognized, …
      time        A    nonce-fresh, clock-consistent,
                       assertion-counter-monotonic, …
      drapeaux         aucun

  Chaîne complète : clé Secure Enclave (7 ms), clé App Attest (37 ms),
  attestation de 5 810 octets validée **jusqu'à la racine publiée par Apple**
  (1 424 ms), enrôlement `attested: true`, nonce de profil `core`, scellement
  **41 ms**, enveloppe de **438 octets**, verdict rendu en **19 ms**.

  Comparaison avec la répétition Android du même jour : enveloppe 438 octets
  contre 742, et vérification 19 ms contre 410. Les deux écarts ont la même
  cause — le jeton Play Integrity est volumineux et doit partir chez Google pour
  être déchiffré, quand l'assertion App Attest est compacte et se valide **hors
  ligne**. C'est la conséquence, mesurée, du mode de déchiffrement tranché par
  contrainte en phase B.

  `STRONG` mérite une note : il n'est atteignable que parce que le profil est
  `core`. Le plafond de recapture d'ADR-0005 s'applique à `capture`, pas au
  noyau — une enveloppe qui n'affirme rien du monde physique n'a pas à payer une
  attaque qui ne la concerne pas. C4.2 fera retomber `origin` à B, et ce sera
  correct.

  **Ce que ce jalon ne dit pas.** Il vaut pour le chemin *développement* :
  l'`aaguid` est `appattestdevelop`, et une compilation de distribution produit
  `appattest` avec une racine différente. Le serveur sait traiter les deux
  (`PROBATIVE_APPATTEST_ENV`), mais **aucun vecteur de production n'existe**.
  Il ne dit rien non plus d'Android, dont la sonde A4.1 n'a toujours pas tourné
  sur SM-X200 — la répétition sur émulateur ne remplace pas une clé matérielle.

  Quatre obstacles rencontrés, tous instructifs et aucun deviné :

  - **`Info.plist` synthétisé contre `Info.plist` écrit.** Deux des clés requises
    sont des *dictionnaires*, que `INFOPLIST_KEY_*` ne sait pas porter. L'écrire
    entièrement à la main coûte l'ossature que Xcode injecte, et l'installation
    est refusée : « Failed to get the identifier for the app to be installed ».
    La bonne réponse est un fichier **partiel** fusionné avec la synthèse.
  - **La permission « réseau local » ne se voit pas dans l'erreur.** `-1009`
    annonce une absence d'Internet alors que l'appareil venait d'atteindre les
    serveurs d'Apple. Le client distingue donc explicitement transport et refus
    serveur, sans quoi on cherche la panne du mauvais côté.
  - **L'extraction de l'UDID de `CLAUDE.md` était fausse** : `awk '{print $3}'`
    tombe sur un mot du *nom* de l'appareil dès qu'il contient des espaces —
    « iPhone 16 de Yannick ». Remplacée par une extraction du motif d'UUID.
  - **`timeout` n'existe pas sur macOS**, et `devicectl … --console` ne rend pas
    la main : lancer en arrière-plan puis relire le journal.

- 2026-08-13 : **C4.2 faite — une photo réelle est sous le sceau.** iPhone 16,
  iOS 26.6, profil `capture`. Verdict `STANDARD`, `integrity`/`position`/`time`
  au grade A, `origin` à B par le seul plafond de recapture — donc **le maximum
  atteignable en v0.1**, et le seul motif de `level_reason`.

  C'est la première enveloppe du dépôt qui décrit quelque chose du monde
  physique : 2 484 264 octets de JPEG, 4032×3024, position GNSS à 8 m avec un
  point de 1 138 ms d'âge au déclenchement, corroborée par le baromètre
  (`baro-consistent`) et l'accéléromètre (`motion-present`).

  **Inconnue n° 2 levée.** Capture **1 904 ms**, scellement **49 ms**,
  vérification **280 ms**. La capture domine de deux ordres de grandeur, comme
  A5 et C3 le laissaient prévoir — la fraîcheur ne coûte rien. Le seuil de
  3 000 ms de `max_sign_latency_ms` tient, mais la marge est mince : c'est ce
  qui transforme les trois pièges ci-dessous en questions de conception plutôt
  qu'en anecdotes.

  Trois erreurs commises puis mesurées, dans cet ordre :

  - **corroboration collectée après l'obturateur** : +4,2 s dans `media[6]`,
    `origin` à C pour « latence anormale ». Le champ censé discriminer une
    injection n'accusait que l'ordonnancement du client. Position et
    corroboration courent désormais *pendant* l'acquisition ;
  - **premier point CoreLocation = point de cache**, 42 922 ms d'âge,
    `position` à C. On attend maintenant un point sous un âge plafond, sans
    jamais masquer l'âge réel de celui qu'on finit par retenir ;
  - **`CLLocationManager` créé sur un fil sans boucle d'exécution** ne délivre
    jamais ses rappels. Aucune erreur, juste un délai qui expire — la panne
    ressemble trait pour trait à une absence de signal GPS.

  Chacune produisait un verdict *plausible et faux* : une latence anormale
  sans anomalie, un point ancien alors qu'un point frais existait, une absence
  de position sur un appareil qui en avait une. C'est exactement la classe de
  défaillance que le banc de triche devra provoquer volontairement.

  **Un manque de la spec, trouvé par l'implémentation.** Les valeurs de
  `claim` n'ont aucune unité normative. `baro-alt` doit être en mètres — le
  vérificateur le compare à `position[4]` — mais rien ne le dit ; `baro` est en
  hectopascals sur Android (`Sensor.TYPE_PRESSURE`) et en kilopascals sur iOS.
  Deux plateformes auraient rapporté la même mesure à un facteur dix près sans
  qu'aucun test ne s'en aperçoive. Le cœur iOS convertit ; **la spec doit le
  rendre normatif**.

  Reste, côté iOS : le chemin de production (`appattest`, racine différente),
  et le chaînage d'enveloppes. Côté Android, A4.1 puis A4.2 — toujours en
  attente d'une SM-X200.

- 2026-08-13 : **préambule d'autorisations — la sonde iOS devient pilotable sans
  intervention.** Les campagnes C4.2 avaient été erratiques, et la cause n'était
  pas le hasard : **chaque autorisation était demandée au moment où son capteur
  servait**, donc sa boîte de dialogue s'affichait *pendant* que le délai
  d'attente courait. Le relevé expirait, et chaque cas se présentait sous un
  symptôme qui ne nommait jamais la cause :

  | Autorisation | Symptôme observé | Ce qu'on soupçonne à tort |
  |---|---|---|
  | caméra | capture sans image | pipeline photo |
  | position | délai expiré | absence de signal GPS |
  | mouvement | `baro-alt` et `baro` absents | baromètre indisponible |
  | réseau local | `-1009`, « connection appears to be offline » | serveur injoignable |

  Le cœur expose désormais `Sensors.locationAuthorization`,
  `motionAuthorization` et leurs demandes — surface légitime, parce que **tout
  intégrateur appelant `capture()` doit pouvoir demander avant, lui aussi**. La
  démonstration ajoute un écran de préambule qui les sollicite **en séquence**,
  jamais en parallèle : iOS n'affiche qu'une boîte à la fois et jette
  silencieusement les demandes concurrentes.

  Trois points appris :

  - **Le réseau local n'a aucune interface d'état.** On ne peut ni l'interroger
    ni la demander à l'avance : la boîte s'affiche à la première requête, qui
    échoue. Le préambule fait donc **échouer cette requête exprès**, hors du
    chemin de mesure, plutôt que de laisser une campagne la payer.
  - **L'autorisation de mouvement ne bloque pas le départ.** `readyForCapture`
    n'exige que caméra et position : le mouvement est une corroboration, pas une
    condition. Sans lui l'enveloppe reste valide, `position` perd seulement
    `baro-consistent`. La distinction a tenu à l'épreuve.
  - **`CMAltimeter.authorizationStatus()` n'est pas à jour immédiatement après
    la demande.** L'en-tête affichait « mouvement ? » alors que le baromètre
    répondait. L'état est donc **relu au lancement de la sonde**, jamais hérité
    du préambule — un en-tête faux est pire qu'absent.

  **Éprouvé à froid, ce qui est le seul test qui compte** : application
  désinstallée — ce qui remet les autorisations à zéro — puis réinstallée. La
  sonde est allée jusqu'à `STANDARD` avec les quatre réclamations **du premier
  coup**, là où il fallait auparavant deux ou trois lancements. L'en-tête
  `autorisations camera ✓ position ✓ mouvement ✓ reseau ✓` ouvre le journal, et
  il est *imprimé* et pas seulement affiché : un extrait rapatrié par
  `--console` doit permettre de distinguer un capteur muet d'une autorisation
  manquante.

- 2026-08-13 : **revue de la journée — quatre défauts trouvés, tous corrigés.**
  Les suites étaient au vert avant comme après : aucun de ces défauts n'aurait été
  trouvé par un test, ce qui est précisément la raison de relire.

  - **Course de données dans `LocationDelegate`.** `freshest` est écrit par les
    rappels de CoreLocation — donc sur la file principale — et l'expiration du
    délai le lisait depuis une file de fond. Le pire cas n'est pas une valeur
    périmée mais un **sur-relâchement ARC**, donc un plantage intermittent et
    invisible en test. Tout l'état des deux délégués est désormais touché sur la
    file principale, sans exception.

    `@MainActor` aurait été plus élégant mais **ne compile pas** :
    `CLLocationManagerDelegate` n'est pas isolé, si bien qu'annoter la classe rend
    sa conformité illégale. D'où `@unchecked Sendable` sous discipline énoncée —
    la seule forme possible ici, et il fallait l'essayer pour le savoir. Quatre
    avertissements de concurrence, qui deviendront des erreurs en mode Swift 6,
    sont éteints ; la compilation iOS est propre.

  - **`Camera.capture()` pouvait attendre indéfiniment.** Rien n'oblige
    AVFoundation à rappeler : une session interrompue ne produit ni photo ni
    erreur. Un scellement suspendu **sans message** est le pire des échecs pour
    une campagne, puisqu'il ne laisse rien à lire. Délai de garde ajouté, généreux
    à dessein — il ne doit jamais interrompre une capture lente, seulement une
    capture morte.

  - **`PerPlatformVerifier` n'avait aucun test.** Classe ajoutée le jour même,
    dont le comportement décisif est de **lever** plutôt que rendre un verdict
    défavorable sur une plateforme non câblée. Trois tests couvrent maintenant
    l'aiguillage, le refus, et le filtrage des plateformes absentes.

  - **Trois commandes de `CLAUDE.md` étaient fausses**, dont deux qui coûtent une
    campagne : le serveur y était lancé depuis `verifier-python/`, où le `.env`
    n'est pas trouvé — ce que la journée avait pourtant établi ; et `ruby` y
    désignait le Ruby système, dépourvu du gem `xcodeproj`. Corrigées et
    **exécutées** pour vérifier, plutôt que relues.

  Réserve honnête : les correctifs iOS compilent proprement pour l'appareil mais
  **n'ont pas été rejoués dessus** — l'iPhone s'était déconnecté. Le changement
  est structurel à logique constante, mais une campagne de confirmation reste due.
