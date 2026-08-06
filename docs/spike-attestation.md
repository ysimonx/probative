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
- [x] `./gradlew :core:assembleRelease` produit un AAR consommable seul (12 Ko,
      aucune dépendance d'exécution) — condition ADR-0003 vérifiée dès le squelette.

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

- [ ] Génération ES256 Keystore, `setAttestationChallenge(nonce)`, StrongBox si
      disponible avec repli documenté, `setUserAuthenticationRequired(false)`.
- [ ] Export de la clé publique X9.62 non compressée, `kid` = SHA-256.
- [ ] Appel `POST /enroll` du serveur de dev, chaîne de certificats transmise
      (validée en phase B seulement).
- [ ] Test instrumenté sur appareil : la clé est bien `hardware-backed`
      (`KeyInfo.securityLevel`).

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

- [ ] `Package.swift`, cible bibliothèque sans dépendance framework, script de
      production du XCFramework, application de démonstration à part.

### C2 — Encodeur CBOR canonique + COSE_Sign1 en Swift

- [ ] Mêmes exigences qu'en A2, validé contre les **mêmes vecteurs d'or**.

### C3 — Clé et enrôlement App Attest

- [ ] `DCAppAttestService.generateKey()`, attestation initiale transmise à
      `POST /enroll` (validée en phase D), `kid` cohérent avec le `keyId` stocké.
- [ ] Clé de signature d'enveloppe Secure Enclave, export public X9.62, même `kid`
      que la convention Android.

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
