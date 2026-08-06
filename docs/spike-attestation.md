# Plan du spike d'attestation natif

**Statut : en cours. Ce document pilote le spike, puis sera archivé dans les ADR
pour ce qui relève des décisions.**

## Objectif

Produire, depuis un appareil réel — Android d'abord, iOS ensuite — une enveloppe
`ac/0.1` que le vérificateur Python accepte. Le critère de sortie est binaire :
la boucle « capture sur appareil → enveloppe → vérification serveur » passe au vert,
avec la validation d'attestation réelle (étape 5 du pipeline), pas le substitut.

`verifier-python/tests/factory.py` reste l'implémentation de référence : si le natif
produit une enveloppe que la fabrique ne saurait pas produire, c'est le natif qui
s'écarte de la spécification (voir aussi ADR-0003 : les cœurs sont des artefacts
autonomes, AAR et XCFramework, sans dépendance à un framework).

## Inconnues que le spike doit lever

1. **`requestHash` Play Integrity.** L'API standard prend une *chaîne* (≤ 500 octets
   documentés) ; R1 produit un condensat de 32 octets *bruts*. Il faut fixer l'encodage
   (vraisemblablement base64url sans bourrage), le valider empiriquement, puis réviser
   ADR-0002 et la spec §3/R1 pour rendre cet encodage normatif. Le
   `PlayIntegrityVerifier` serveur devra comparer avec le même encodage.
2. **Latence capture→signature (`media.6`)** sur appareil d'entrée de gamme. Elle
   conditionne l'exploitabilité du champ comme discriminant d'injection. Protocole :
   mesurer sur au moins un appareil bas de gamme et un milieu de gamme, en conserver
   les distributions, et calibrer les seuils dans les constantes de `grading.py`.
3. **Chaînage Android** (spec §9, décision ouverte) : chaîne de hachage locale ou
   compteur Keystore. Le spike implémente la chaîne de hachage locale, la plus simple,
   et documente ce qui pousserait vers l'autre option.

## Phase 0 — Outillage de vérification (verifier-python)

Aujourd'hui seul `pytest` exerce le vérificateur, sur des enveloppes de la fabrique.
Il faut une cible que les appareils réels peuvent viser :

- **Mini serveur de développement** (module `devserver.py` ou paquet séparé, hors API
  publique) : trois routes — `POST /enroll` (enregistre la clé publique, calcule le
  `kid`), `POST /nonce` (émet un nonce à durée de vie courte), `POST /verify` (reçoit
  enveloppe + média, retourne le résultat structuré JSON). S'appuie sur
  `InMemoryNonceStore` / `InMemoryDeviceStore` existants et `NullAttestationVerifier`
  au départ, remplaçable par les vérificateurs réels des phases B et D. Aucune décision
  de validité nouvelle : c'est un simple câblage de `Verifier`.
- **Vecteurs d'or** : un script (`tools/gen_vectors.py`) qui fige, à partir de
  `factory.py` avec clé et nonce déterministes, les octets attendus de
  `payload_bytes`, `protected_bytes`, `Sig_structure` et de l'enveloppe complète.
  Les encodeurs CBOR natifs devront reproduire ces octets **à l'identique** — c'est
  le test de canonicité (spec §7) le moins cher et le plus discriminant.
- À l'enrôlement, la validation complète des chaînes d'attestation de clé (racine
  Google / Apple) n'est **pas** dans la phase 0 : le serveur de dev enregistre la clé
  telle quelle. La validation réelle arrive en phases B et D.

## Phase A — Cœur Android (`mobile/android/`)

Projet Gradle : module `:core` publiable en AAR (aucune dépendance UI ni framework),
module `:demo` application minimale qui consomme l'AAR et parle au serveur de dev.

Ordre de travail, chaque étape validée contre les vecteurs d'or ou le serveur de dev :

1. **Encodeur CBOR canonique + COSE_Sign1** en Kotlin pur, strict nécessaire, dans
   l'esprit de `cose.py` côté serveur (ADR-0001 : surface minimale, pas de bibliothèque
   généraliste). Validé octet à octet contre les vecteurs d'or.
2. **Clé ES256 Keystore** avec `setAttestationChallenge(nonce)`, StrongBox si
   disponible ; enrôlement contre le serveur de dev ; `kid` = SHA-256 de la clé
   publique X9.62 non compressée (comme `factory.kid_for`).
3. **Capture CameraX** : octets JPEG bruts du capteur, SHA-256, dimensions, horloges
   (`currentTimeMillis`, `elapsedRealtime`), position (fused provider + ancienneté du
   point), posture (débogueur, émulateur, mock location, mode développeur).
4. **Play Integrity, API standard** : `requestHash` = R1, d'abord contre le
   `NullAttestationVerifier` (jeton opaque transmis tel quel), pour valider la
   structure d'enveloppe de bout en bout avant que la phase B n'existe.
5. **Chaînage** (`payload[7]`) : SHA-256 de l'enveloppe précédente, persisté localement.
6. **Corroboration minimale** : `baro`, `baro-alt`, `motion` (fenêtre 10 s), `steps`.
   Types manquants omis, jamais simulés.
7. **Mesure de latence** `media.6` sur appareils réels (inconnue n° 2).

Sortie de phase : le `:demo` produit une enveloppe acceptée par le serveur de dev
(substitut d'attestation), latences mesurées, AAR consommable seul.

## Phase B — `PlayIntegrityVerifier` serveur

Implémenter `attestation/play_integrity.py` : déchiffrement et validation du jeton
(API Play Developer ou clés de déchiffrement locales — à trancher pendant la phase),
vérification du verdict d'appareil et d'application, comparaison du `requestHash` au
défi R1 recalculé, mapping vers `AttestationOutcome`. Tests avec jetons réels capturés
en phase A, plus tests d'attaque référencés au modèle de menace. Ajouter la validation
de la chaîne d'attestation de clé Android à l'enrôlement.

Sortie de phase : la boucle Android complète passe au vert **sans** substitut.
Réviser ADR-0002 (encodage du `requestHash`, inconnue n° 1).

## Phase C — Cœur iOS (`mobile/ios/`)

Package SwiftPM produisant un XCFramework, plus une application de démonstration.
Symétrique de la phase A : encodeur CBOR/COSE Swift validé contre les mêmes vecteurs
d'or, clé Secure Enclave, `DCAppAttestService.generateKey()` à l'enrôlement,
`generateAssertion(clientDataHash: R1)` à la capture avec compteur dans
`freshness[3]`, capture AVFoundation, posture iOS. Pas de chaînage : le compteur
d'assertion joue ce rôle (spec §2.3).

## Phase D — `AppAttestVerifier` serveur

Implémenter `attestation/app_attest.py` : validation de l'objet d'attestation à
l'enrôlement (chaîne x5c jusqu'à la racine App Attest d'Apple), vérification des
assertions à la capture, compteur strictement croissant (étape 6 du pipeline).

Sortie de phase : boucle iOS complète au vert, et fin du spike.

## Clôture du spike

- Geler la spec d'enveloppe (elle est en « statut : proposition, à geler après le
  spike ») ; réviser ADR-0002 et trancher le chaînage Android (spec §9).
- Reporter les latences mesurées dans les constantes de `grading.py`.
- Alors seulement, ouvrir le chantier des liaisons minces `bindings/` (ADR-0003).

## Prérequis logistiques — hors code

- **Android** : appareil réel (Play Integrity et StrongBox ne répondent pas de manière
  représentative sur émulateur), application déclarée dans la Play Console (une piste
  interne suffit), projet Google Cloud lié pour l'API standard.
- **iOS** : compte développeur Apple payant, appareil réel (App Attest est indisponible
  sur simulateur).
- Aucun matériel cryptographique réel versionné, y compris les jetons capturés pour
  les tests des phases B et D : voir `.gitignore` avant tout commit de fixtures.
