# probative

## Pourquoi ce projet existe

Une photo géolocalisée ordinaire ne prouve rien : l'EXIF s'édite, le GPS se simule avec
une application grand public, et des coordonnées incrustées sur l'image ne sont que des
pixels — n'importe qui peut les y écrire. Dès qu'une décision dépend de la photo, il faut
une preuve opposable.

Ce dépôt produit une bibliothèque mobile et un vérificateur serveur qui établissent
qu'une image a été prise **par ce capteur, à cet endroit, à cet instant**, sur un
appareil non compromis.

Projet personnel indépendant, destiné à être réutilisé sur plusieurs projets et
éventuellement publié. Licence Apache-2.0.

## Invariants — ne jamais transiger

1. **Le client collecte et signe des preuves, le serveur juge.** Aucune décision de
   validité sur l'appareil. L'API publique n'expose jamais de booléen de confiance.
2. **La règle R1 ne s'assouplit pas.** Le défi soumis au service d'attestation vaut
   exactement `SHA-256(payload_bytes || nonce)`. Sans elle, l'enveloppe atteste
   seulement qu'un appareil sain existe quelque part — ce qui ne prouve rien.
3. **Aucun vocabulaire métier dans ce dépôt.** Pas de « chantier », pas de nom de
   client, pas de domaine applicatif. Uniquement `capture`, `subject`, `evidence`.
   Cette règle protège la réutilisabilité et l'antériorité du code ; elle prime sur
   la lisibilité d'un exemple.
4. **Le format raisonne en propriétés, pas en plateformes.** Android et iOS atteignent
   le même niveau par des chemins différents. Aucun champ obligatoire propre à une
   plateforme.
5. **Le résultat de vérification est structuré par propriété**, jamais un score seul.
   `level_reason` est obligatoire : un rejet sans motif exploitable est ingérable en
   support. Depuis ADR-0005, **l'ensemble des propriétés notées dépend du profil
   déclaré** — le résultat porte donc `profile`, et un profil inconnu fait refuser de
   juger plutôt que se replier sur le noyau.
6. **Le noyau ignore le type de contenu.** Un besoin propre à un médium se traite par un
   champ optionnel, jamais par du code qui suppose une image. Un nouveau profil ne se
   justifie que si une propriété apparaît, disparaît, ou change de règle de notation.
7. **Le verdict ne dépend jamais du canal.** L'enveloppe s'authentifie par elle-même :
   R2 établit déjà quel appareil l'a produite, au niveau du message. Une sécurité de
   canal — mTLS, certificat client, jeton de session — relève du déploiement et ne doit
   jamais entrer dans le jugement, sous peine de rendre la preuve invérifiable une fois
   la session close. Voir spec §6. *Placé en fin de liste à dessein : insérer un
   invariant au milieu décale la numérotation et fait mentir les renvois des ADR.*

## Documents de référence — à lire avant toute modification de fond

| Fichier | Rôle |
|---|---|
| `docs/architecture.html` | Vue d'ensemble illustrée du mécanisme, séquences et FAQ. Point d'entrée pour comprendre ; ne fait pas autorité. Les deux diagrammes de séquence sont générés par `tools/gen_sequences.py` — ne pas les éditer à la main. |
| `docs/threat-model.md` | Spécification de référence. Toute fonctionnalité doit répondre à une menace identifiée. |
| `docs/envelope-spec.md` | Format `probative/0.1`, noyau et profils (§2.5), règles de liaison R1/R2/R3, ordre de vérification |
| `docs/decisions/` | ADR. Les compléter plutôt que revenir silencieusement sur un choix. |
| `spec/envelope-v0.1.cddl` | Extrait normatif de la spec. **Aucun générateur** : à tenir synchrone à la main, dans les deux sens. Un test le vérifierait mieux qu'une consigne — non écrit à ce jour. |
| `docs/etat-de-l-art.md` | Solutions voisines (Approov, Guardsquare, Truepic, C2PA, ProofMode) et ce qui distingue réellement ce dépôt. À relire avant tout arbitrage de feuille de route ; **daté**, revérifier les faits avant de s'en servir. |

## Structure

```
docs/             Modèle de menace, spec d'enveloppe, ADR, vue d'ensemble
spec/             Schéma CDDL normatif — extrait de docs/envelope-spec.md, à garder
                  synchronisé à la main (aucun générateur à ce jour)
tools/            Génération des figures de la documentation
verifier-python/  Vérificateur serveur
  tests/vectors/        Vecteurs d'or synthétiques, régénérés par tools/gen_vectors.py.
                        Le test compare le dossier à une régénération : n'y déposer
                        aucun fichier étranger.
  tests/device-vectors/ Captures réelles d'appareils, non régénérables. Socle des
                        phases B et D — sans elles on code contre une documentation.
mobile/android/   Cœur natif Kotlin (AAR) — :core, plus :demo qui porte les sondes
mobile/ios/       Cœur natif Swift (XCFramework) — paquet SwiftPM, plus demo/ qui
                  porte la sonde C3. Le .xcodeproj est généré, non versionné.
bindings/         Liaisons minces : plugin Flutter fédéré, module React Native — non commencées
```

Les applications de démonstration ne sont pas décoratives : App Attest et Play
Integrity exigent une application provisionnée, qu'un bundle de test n'est pas.
C'est leur seule raison d'être — ne rien y loger qui appartienne au cœur.

## Commandes

### Vérificateur

```bash
cd verifier-python
source .venv/bin/activate
pip install -e ".[dev]"
pytest              # 192 tests doivent passer
ruff check .
mypy src
```

### Android — appareil réel requis pour les sondes

```bash
cd mobile/android
# ANDROID_HOME n'est pas dans l'environnement de ce poste ; le SDK est en
# ~/Library/Android/sdk. Préfixer, ou renseigner sdk.dir dans local.properties.
ANDROID_HOME=$HOME/Library/Android/sdk \
  ./gradlew :core:testDebugUnitTest        # unitaires, sans appareil
./gradlew :core:connectedDebugAndroidTest  # instrumentés, appareil branché

# Vecteur d'appareil (chaîne d'attestation de clé). Sort par logcat en tronçons
# numérotés : Gradle désinstalle le paquet de test en fin de campagne, et
# Android 11+ interdit à adb de lire Android/data d'une autre application.
adb logcat -c && ./gradlew :core:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.probative.core.keys.KeystoreVectorDeviceTest
adb logcat -d -s PROBATIVE_VECTOR

# Sonde A5 — Play Integrity. Le numéro de projet Google Cloud est une donnée de
# compte, passée en propriété et jamais écrite dans le code.
./gradlew :demo:installDebug -Pprobative.cloudProjectNumber=487335590129
adb shell am start -n org.probative.demo/.MainActivity
adb logcat -d -s PROBATIVE_A5
```

### iOS — appareil réel et compte payant requis pour App Attest

```bash
cd mobile/ios
swift test                        # 18 tests sur l'hôte, App Attest se saute
./scripts/make_xcframework.sh     # artefact autonome
ruby scripts/make_demo_project.rb # projet Xcode, non versionné

UDID=$(xcrun devicectl list devices | awk '/available/{print $3; exit}')
xcodebuild -project demo/ProbativeDemo.xcodeproj -scheme ProbativeDemo \
  -destination "id=$UDID" -derivedDataPath demo/build -allowProvisioningUpdates build
xcrun devicectl device install app --device "$UDID" \
  demo/build/Build/Products/Debug-iphoneos/ProbativeDemo.app
# Sans --console : ce drapeau attend la fin de l'application et donne
# l'impression que la commande est bloquée.
xcrun devicectl device process launch --device "$UDID" --terminate-existing org.probative.demo
xcrun devicectl device copy from --device "$UDID" --domain-type appDataContainer \
  --domain-identifier org.probative.demo --source Documents/c3-fixture.json --destination ./
```

## Conventions

- Python ≥ 3.11, typage strict, `from __future__ import annotations`.
- Docstrings et commentaires **en français**. Identifiants en anglais.
- Les commentaires expliquent *pourquoi*, pas *quoi*.
- Tout seuil de décision va dans `GradingPolicy` (`grading.py`), jamais en dur dans le
  code : ils seront recalibrés sur données réelles, et un déploiement peut les régler.
  Deux bornes à cette souplesse : **ce qui change le format se tranche, ce qui change
  l'exploitation se configure** ; et **une option peut resserrer, jamais desserrer un
  angle mort assumé** — d'où `RECAPTURE_CAP`, qui reste en dur. Tout écart au défaut
  voyage dans `VerificationResult.policy` : un verdict calculé sous d'autres règles
  n'est pas comparable à un verdict calculé sous celles d'origine.
- Chaque test d'attaque référence une surface d'attaque du modèle de menace, **définies en
  `docs/threat-model.md` §4 bis** : `test_s1_` position, `test_s2_` contenu, `test_s3_` temps,
  `test_s4_` client. Un test qui ne se rattache à aucune surface signale soit un test mal
  cadré, soit une surface manquante dans le modèle.
- Entrée hostile : décodage défensif via `Mapping` / `Sequence`, jamais `dict` / `list`
  (cbor2 en mode canonique restitue des types immuables).
- Aucun matériel cryptographique réel versionné. Voir `.gitignore`.

## État actuel

| Composant | État |
|---|---|
| Modèle de menace, spec d'enveloppe, ADR | Rédigés |
| Noyau et profils (ADR-0005) | **Fait de bout en bout** : spec §2.5, CDDL, vérificateur, vecteurs, et les deux cœurs natifs |
| Vérificateur Python, pipeline étapes 1–10 | Fonctionnel, 192 tests au vert |
| `AppAttestVerifier` — **phase D faite** | Attestation d'enrôlement validée **jusqu'à la racine publiée par Apple**, assertion validée par enveloppe. Éprouvé contre le vecteur iPhone 16 réel, 26 tests |
| `PlayIntegrityVerifier` — **phase B faite** | Jeton déchiffré par `decodeIntegrityToken`, `requestHash` recalculé et confronté, verdicts traduits. Chaîne d'attestation de clé ancrée à la racine Google (`key_attestation.py`). 35 tests |
| Vecteurs d'or | Trois jeux : `android`, `ios` (profil `capture`) et `core` (profil noyau). Reproduits octet à octet par Kotlin **et** Swift |
| Vecteurs d'appareil | Android (chaîne à 4 certificats, SM-X200) et iOS (App Attest, iPhone 16) versionnés dans `tests/device-vectors/` |
| Cœur natif Android | A1–A3 et **A5 faites, validées sur SM-X200**. `:demo` restauré, porte la sonde A5. Prochaine : A4, capture CameraX |
| Cœur natif iOS | C1–C3 faites ; **C3 validée sur appareil réel** (iPhone 16, iOS 26.6), assertion R1 exercée. Prochaine : C4, capture AVFoundation |
| Liaisons Flutter / React Native | Non commencées |
| Banc de triche | Non commencé |

**Ce qui est réellement prouvé, et ce qui ne l'est pas.** Les deux plateformes
produisent une clé matérielle liée à un défi R1, et le lien est vérifié *par
recalcul* — côté Android, le défi que le TEE inscrit dans l'extension
`1.3.6.1.4.1.11129.2.1.17` vaut bien `SHA-256(payload ‖ nonce)`.

Il faut distinguer deux preuves de nature différente, souvent confondues :

- **L'attestation de clé** (chaîne de 4 certificats) est produite **hors ligne**
  par la puce. Aucun serveur n'est interrogé — c'est voulu, cela fonctionne sans
  réseau. ~~On a vérifié que la chaîne est cohérente, jamais que sa racine est
  celle que Google publie.~~ **Levé le 2026-08-12** : `key_attestation.py`
  confronte la racine aux racines publiées par Google, et un test forge une chaîne
  cohérente de bout en bout pour vérifier qu'elle est bien refusée.
- **Le jeton Play Integrity** est bien obtenu **auprès des serveurs de Google**.
  ~~Mais il est chiffré et n'a jamais été ouvert.~~ **Levé le 2026-08-12** : un
  jeton réel de la SM-X200 a été déchiffré (HTTP 200), et le `requestHash` restitué
  vaut exactement le R1 recalculé côté serveur. `appRecognitionVerdict` valait bien
  `UNRECOGNIZED_VERSION`, comme prévu, et `deviceRecognitionVerdict`
  `MEETS_DEVICE_INTEGRITY`.

**Les deux plateformes sont désormais ancrées.** Côté iOS depuis la phase D
(`apple-app-attest-root-ca.pem`), côté Android depuis le 2026-08-12
(`google-hardware-attestation-roots.pem`, deux racines). **Apple et Google ont
signé, et on l'a vérifié dans les deux cas.**

Deux pièges retenus de l'ancrage Android, qui ne s'inventent pas :

- **L'ancrage porte sur la clé publique, jamais sur l'identité du certificat.**
  Google a réémis sa racine RSA en 2022 en conservant la clé : la SM-X200 porte un
  certificat de série et de validité différentes de celui publié aujourd'hui. Un
  ancrage par empreinte aurait rejeté une chaîne légitime, et seulement sur du
  matériel ancien — donc tard.
- **Une seconde racine, EC P-384, est effective depuis février 2026.** Les deux
  doivent être acceptées.

Trois points appris en écrivant D, qui valent d'être retenus :

- **Deux clés distinctes vivent dans l'appareil.** La clé de signature du format
  (Secure Enclave, désignée par le `kid`) et la clé App Attest (gérée par
  `DCAppAttestService`, incapable de signer autre chose qu'une assertion). Les
  confondre bloque net. `DeviceRecord.attestation_key` porte la seconde.
- **R1 est vérifiée cryptographiquement sur iOS, pas par comparaison de champ.**
  Le `clientDataHash` ne circule pas dans l'enveloppe : le serveur le recalcule, et
  la signature de l'assertion ne se vérifie que s'il est identique. Un contenu
  forgé fait échouer la signature, pas un test d'égalité.
- **Le compteur d'assertion de l'en-tête de fraîcheur n'est signé par rien.**
  Celui de `authenticatorData` l'est. Quand les deux existent, seul le second fait
  foi et un désaccord est un rejet — faiblesse réelle du pipeline, fermée par D.

Reste que **aucune photo n'a encore été prise** : A4 et C4 sont à faire. La phase B
est close à un câblage près — la validation de chaîne existe et est éprouvée, mais la
route d'enrôlement ne l'appelle pas encore.

## Prochaine étape

**Spike d'attestation natif** — plan détaillé et phases dans
`docs/spike-attestation.md`. Cible précise : produire une enveloppe qu'un appareil
réel fait accepter par le vérificateur. `verifier-python/tests/factory.py` est
l'implémentation de référence — si le natif produit une enveloppe que la fabrique ne
saurait pas produire, c'est le natif qui s'écarte de la spécification.

Les cœurs du spike doivent être livrés comme artefacts autonomes (AAR, XCFramework),
sans dépendance à un framework : c'est la condition de la stratégie multi-frameworks
Flutter + React Native (ADR-0003). Tout le chemin critique reste natif ; le pont
Dart/JS ne reçoit que l'enveloppe signée, opaque.

Nuance apparue en A5 : `:core` dépend désormais de `com.google.android.play:integrity`.
Contrairement à DeviceCheck côté iOS, ce n'est pas un framework système. L'AAR n'est
donc plus sans dépendance externe. Le type `StandardIntegrityTokenProvider` est
encapsulé dans une classe opaque pour que la surface publique du cœur ne fasse pas
fuir un type propriétaire — mais la dépendance existe et il faut l'assumer, ou
l'isoler dans un module séparé si elle gêne un jour les liaisons.

### Où en sont les inconnues

1. **`requestHash` Play Integrity — levée sur la taille.** base64url sans bourrage :
   43 caractères pour un plafond de 500. Aucun niveau d'indirection nécessaire.
   *Reste* : confirmer que Play restitue la chaîne intacte, ce qui exige de
   déchiffrer un jeton — donc la phase B. Une divergence d'encodage entre client et
   serveur casserait R1 **silencieusement** : c'est le pire mode de défaillance, à
   traiter avant de figer ADR-0002.
2. **Latence — déplacée, pas levée.** La fraîcheur ne coûte rien : 36–39 ms sur
   SM-X200, 18 ms sur iPhone 16. Le préchauffage Play Integrity, lui, coûte 1 313 ms
   à froid et doit rester au démarrage. Conclusion : le sujet de `media.6` est la
   **capture elle-même**, à mesurer en A4/C4.
3. **Chaînage Android** (spec §9) : inchangée, non instruite.
4. **Horodatage par un tiers, RFC 3161** (spec §9) : ouverte. **Ne relève pas de la
   sécurité** — le nonce encadre déjà la capture des deux côtés, et un jeton
   d'horodatage ne resserre aucune borne. Relève de l'**opposabilité** : l'encadrement
   par le nonce est une preuve que le serveur se fabrique à lui-même, là où un jeton
   de tiers accrédité se vérifie sans avoir à faire confiance à ce serveur. Trois
   garde-fous déjà posés : jamais une propriété notée ; calculé sur l'empreinte de
   l'enveloppe après signature, donc hors du chemin de capture ; et **l'appel à
   l'autorité se fait depuis le serveur**, jamais depuis l'appareil — sans quoi les
   identifiants de l'autorité descendraient dans un client posé comme hostile.
   Corollaire noté en spec §9 : la forme complète est **deux** jetons, un sur le nonce
   à l'émission et un sur l'enveloppe à la réception, faute de quoi la borne basse de
   l'encadrement reste autoproclamée.

   C'est le seul manque qu'aucun travail cryptographique ne comblera — il est
   réglementaire. Si les cas d'usage visés sont ceux du constat de terrain, cela mérite
   d'être instruit **avant** A4/C4 ; sinon, après. Cela ne déplace jamais la phase B,
   qui reste ce qui rend le reste opposable.

### Deux chantiers ouverts, aucun bloqué

**Phase B — faite le 2026-08-12, à un câblage près.** Les trois réserves sont
tombées : racine Google confrontée, `requestHash` restitué intact et vérifié par
recalcul, jeton déchiffré. Le mode de déchiffrement a été **tranché par
contrainte** et non par préférence — les clés locales exigent une application
disponible sur Google Play, ce que la diffusion hors magasin ne permet pas. C'est
donc un appel à Google par enveloppe, avec ses quatre conséquences assumées
(`docs/play-integrity-service-account.md` §2), et l'authentification passe par la
couture d'ADR-0006 pour ne rien imposer aux déploiements.

*Reste à câbler* : la route d'enrôlement accepte encore la chaîne d'attestation
sans appeler `verify_key_attestation`, et `DeviceRecord.hardware_backed` n'est donc
pas encore renseigné depuis elle. Le module est prêt et éprouvé ; c'est du
branchement.

**A4 / C4 — la capture.** La seule qui mettra enfin une photo sous le sceau, et le
vrai sujet de mesure de latence. Rien ne la bloque ; c'est aussi la plus longue.

### Ce que la phase D n'a pas couvert

Elle valide l'attestation et l'assertion **isolément**, jamais une enveloppe
complète de bout en bout. La sonde C3 a signé une charge utile de substitution, pas
un `COSE_Sign1` : le pipeline ne peut donc pas rejouer ce vecteur. Faire juger une
enveloppe réelle par le vérificateur suppose que le cœur iOS produise une vraie
enveloppe — c'est C4, ou une itération de C3.

Deux points restés hors périmètre, volontairement : le **reçu** App Attest est
conservé mais non validé (cela exige un appel à Apple), et le certificat feuille ne
vaut que **trois jours** — d'où l'horloge injectable de `verify_attestation` et de
`DevService`, sans laquelle tout test de chaîne devient une bombe à retardement.

## Angle mort assumé

La **recapture analogique** n'est pas détectée en v0.1 : position authentique, attestation
valide, contenu faux. Photographier un écran et enregistrer un haut-parleur qui rejoue un
enregistrement sont la même attaque — d'où le nom, qui ne désigne plus un médium.

C'est pour cela que `origin` est plafonné au grade B **dans le profil `capture`**. Le
plafond ne s'applique pas au noyau, qui n'affirme rien sur le monde physique : depuis
ADR-0005, une enveloppe `core` peut atteindre `STRONG`. Ne pas lever le plafond sur
`capture` sans implémenter la détection.
