# Plan du spike d'attestation natif

**Statut : en cours — document de pilotage.** Les cases sont cochées au fur et à
mesure ; une tâche abandonnée ou modifiée est barrée avec une note, jamais effacée
silencieusement. Ce qui relève d'une décision durable part en ADR à la clôture.

## Objectif et critère de sortie

Produire, depuis un appareil réel — Android d'abord, iOS ensuite — une enveloppe
`ac/0.1` que le vérificateur Python accepte. Critère binaire : la boucle
« capture sur appareil → enveloppe → vérification serveur » passe au vert avec la
validation d'attestation **réelle** (étape 5 du pipeline), pas le substitut.

`verifier-python/tests/factory.py` reste l'implémentation de référence : si le natif
produit une enveloppe que la fabrique ne saurait pas produire, c'est le natif qui
s'écarte de la spécification. Les cœurs sont des artefacts autonomes — AAR,
XCFramework — sans dépendance à un framework (ADR-0003).

## Inconnues que le spike doit lever

1. **`requestHash` Play Integrity.** L'API standard prend une *chaîne* (≤ 500 octets
   documentés) ; R1 produit un condensat de 32 octets *bruts*. Fixer l'encodage
   (vraisemblablement base64url sans bourrage), le valider empiriquement, puis
   réviser ADR-0002 et la spec §3/R1 pour le rendre normatif.
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
      surface minimale d'ADR-0001. Module `attested_capture.devserver`, hors API
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
- [x] Appel `POST /enroll` du serveur de dev, chaîne de certificats transmise
      (validée en phase B seulement). Serveur et appareil calculent le **même
      `kid`** : la règle R2 tient de bout en bout, journal serveur à l'appui
      (`POST /enroll 200`).
- [x] Test instrumenté sur appareil : la clé est bien `hardware-backed`
      (`KeyInfo.securityLevel`). Chaîne d'attestation d'au moins 2 certificats ;
      signature brute de 64 octets reconvertie en DER et acceptée par le
      fournisseur JCA.

Point de méthode : le serveur de dev a été rendu joignable par
`adb reverse tcp:8765 tcp:8765` plutôt que par `--host 0.0.0.0`. C'est plus simple
(aucune adresse IP à relever, appareil et hôte n'ont pas besoin d'être sur le même
réseau) et cela évite d'exposer le serveur sur le réseau local. À préférer dans le
commentaire d'en-tête de `KeystoreKeysDeviceTest`.

**Sortie de A3 : atteinte (2026-08-11).** Deux réserves explicites : aucun appareil
doté de StrongBox au banc, donc ce chemin n'est pas exercé — seul le repli l'est ; et
la chaîne d'attestation est transmise sans être validée, ce qui reste la phase B.

### A4 — Capture et collecte

- [ ] CameraX `ImageCapture` : octets JPEG bruts du capteur, SHA-256, type MIME,
      taille, dimensions — l'empreinte est calculée sur les octets qui partiront au
      serveur, sans ré-encodage intermédiaire.
- [ ] `timing` : horloge murale, `elapsedRealtime`, décalage UTC, synchronisation
      automatique de l'heure.
- [ ] `position` : fused provider, précision, ancienneté du point au déclenchement
      (`position.7`), nombre de satellites si disponible.
- [ ] `posture` : débogueur, émulateur suspecté, mode développeur, indicateur de
      position simulée, paquets suspects.
- [ ] Assemblage de la charge utile complète, identique champ à champ à ce que
      `factory.make_payload` sait produire.

### A5 — Fraîcheur Play Integrity (règle R1)

- [ ] Intégration API standard (`StandardIntegrityManager`), préchauffage du
      fournisseur de jetons au démarrage.
- [ ] `requestHash` = encodage retenu de `SHA-256(payload_bytes ‖ nonce)` —
      **inconnue n° 1** : valider empiriquement l'encodage et la taille, noter le
      résultat ici et dans ADR-0002.
- [ ] Jeton opaque dans `freshness[2]`, enveloppe complète signée, acceptée par le
      serveur de dev avec substitut d'attestation.

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

**Sortie de phase A :** le `:demo` produit sur appareil réel une enveloppe acceptée
par le serveur de dev (substitut d'attestation) ; AAR autonome ; latences mesurées.

---

## Phase B — `PlayIntegrityVerifier` serveur

- [ ] Trancher le mode de déchiffrement du jeton : API Play Developer (Google
      déchiffre) ou clés locales — noter la décision et sa justification ici.
- [ ] Implémenter `attestation/play_integrity.py` : déchiffrement, verdicts appareil
      et application, comparaison du `requestHash` au défi R1 recalculé (même
      encodage qu'en A5), mapping vers `AttestationOutcome`.
- [ ] Tests avec jetons réels capturés en phase A — **jamais versionnés**
      (`.gitignore`), chargés depuis un chemin local.
- [ ] Tests d'attaque référencés au modèle de menace (`test_s*_`) : jeton rejoué,
      jeton d'une autre application, `requestHash` d'une autre charge utile.
- [ ] Validation de la chaîne d'attestation de clé Android à l'enrôlement (racine
      Google Hardware Attestation), niveau de sécurité stocké dans `DeviceRecord`.
- [ ] Réviser ADR-0002 : encodage normatif du `requestHash` (inconnue n° 1).

**Sortie de phase B :** boucle Android complète au vert **sans** substitut.

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

- [ ] `DCAppAttestService.generateKey()`, attestation initiale transmise à
      `POST /enroll` (validée en phase D), `kid` cohérent avec le `keyId` stocké.
      *(enveloppe mince `AppAttest` écrite et compilée pour iOS ; test conditionnel
      prêt, sauté hors appareil — App Attest exige un App ID provisionné.)*
- [x] Clé de signature d'enveloppe Secure Enclave, export public X9.62, même `kid`
      que la convention Android — **validé sur l'enclave réelle du Mac hôte**
      (Apple Silicon, même API que l'appareil) : création, export, signature
      vérifiée par CryptoKit ; convention kid confirmée contre le manifest des
      vecteurs, aller-retour Security exact.

### C4 — Capture et collecte

- [ ] AVFoundation : octets JPEG bruts, empreinte, dimensions ; `timing`,
      `position` (CoreLocation + ancienneté), `posture` iOS (`posture[9]`).
- [ ] Corroboration : `baro`/`baro-alt` (CMAltimeter), `motion`, `steps`,
      `activity`.

### C5 — Fraîcheur (règle R1)

- [ ] `generateAssertion(clientDataHash: R1)` — 32 octets bruts, pas de problème
      d'encodage attendu ; compteur d'assertion dans `freshness[3]`.
- [ ] Pas de chaînage `payload[7]` : le compteur joue ce rôle (spec §2.3).
- [ ] Mesure de `media.6` sur un appareil iOS réel, reportée ici.

**Sortie de phase C :** enveloppe iOS acceptée par le serveur de dev (substitut) ;
XCFramework autonome.

---

## Phase D — `AppAttestVerifier` serveur

- [ ] Implémenter `attestation/app_attest.py` : validation de l'objet d'attestation
      à l'enrôlement (chaîne x5c jusqu'à la racine App Attest d'Apple, `keyId`,
      compteur initial), vérification des assertions à la capture.
- [ ] Compteur strictement croissant (étape 6 du pipeline), état dans
      `DeviceRecord`.
- [ ] Tests d'attaque : assertion rejouée, compteur en recul, `clientDataHash`
      d'une autre charge utile.

**Sortie de phase D :** boucle iOS complète au vert — fin du spike.

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

- [ ] Application déclarée dans la Play Console (piste interne suffisante) et
      projet Google Cloud lié pour l'API standard Play Integrity.
- [ ] Appareil Android réel d'entrée de gamme + un milieu de gamme (émulateur non
      représentatif pour Play Integrity et StrongBox).
- [ ] Compte développeur Apple payant.
- [ ] Appareil iOS réel (App Attest indisponible sur simulateur).

## Journal

- 2026-08-06 : plan rédigé, phases 0/A/B/C/D définies. Rien de commencé.
- 2026-08-06 : **phase 0 terminée.** Vecteurs d'or (`tests/vectors/`, générateur
  `tools/gen_vectors.py`, signature RFC 6979) et serveur de dev
  (`attested_capture.devserver`, socle stdlib au lieu de FastAPI — zéro dépendance
  nouvelle). 50 tests au vert. Trouvaille utile pour A2/C2 : les vecteurs
  contiennent du float16, du float32 et du float64 — la demi-précision CBOR est
  incontournable côté natif. Prochaine étape : phase A (squelette Gradle A1).
- 2026-08-06 : **A1 et A2 terminées.** `mobile/android/` : module `:core` (AAR
  autonome, 12 Ko), encodeur CBOR canonique et couche COSE en Kotlin pur, 13 tests
  au vert — les vecteurs d'or sont reproduits octet à octet du premier coup, demi-
  précision comprise. `:demo` différé à A4. Prochaine étape : A3 (clé Keystore et
  enrôlement), qui demande un appareil réel pour ses tests instrumentés.
- 2026-08-06 : **C1 et C2 terminées.** `mobile/ios/` : package SwiftPM
  `AttestedCaptureCore`, encodeur CBOR canonique et couche COSE en Swift, 13 tests
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
