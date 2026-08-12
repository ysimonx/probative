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

- [x] **Vecteur d'appareil capturé** (`KeystoreVectorDeviceTest`, 2026-08-11) —
      pendant de la sonde C3 côté iOS. Chaîne de 4 certificats conservée dans
      `tests/device-vectors/`. Contrôle décisif fait **par recalcul** : le défi
      inscrit par le TEE dans l'extension `1.3.6.1.4.1.11129.2.1.17` vaut bien
      `SHA-256(payload ‖ nonce)`, et `attestationSecurityLevel` confirme
      `TrustedEnvironment` dans l'attestation elle-même, pas seulement d'après ce
      que déclare l'appareil.

**Sortie de A3 : atteinte (2026-08-11).** Deux réserves explicites : aucun appareil
doté de StrongBox au banc, donc ce chemin n'est pas exercé — seul le repli l'est ; et
la chaîne d'attestation est **cohérente avec elle-même mais sans ancre** — sa racine
n'a pas été confrontée à celle publiée par Google, ce qui reste la phase B.

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

- [ ] AVFoundation : octets JPEG bruts, empreinte, dimensions ; `timing`,
      `position` (CoreLocation + ancienneté), `posture` iOS (`posture[9]`).
- [ ] Corroboration : `baro`/`baro-alt` (CMAltimeter), `motion`, `steps`,
      `activity`.

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
