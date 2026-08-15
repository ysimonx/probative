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
| `docs/acquisition-et-liaisons.md` | **Discussion ouverte, rien de décidé.** Prévisualisation, commandes de prise de vue, série de captures et couture avec les liaisons Flutter/RN. Porte deux décisions — la propriété de la session de capture, qui commande tout le reste, et le niveau visé par une série hors ligne — plus les pièges à ne pas redécouvrir. À lire avant d'ouvrir le chantier des liaisons ou de toucher à `Camera`. |
| `spec/envelope-v0.1.cddl` | Extrait normatif de la spec. **Aucun générateur** : à tenir synchrone à la main, dans les deux sens. Un test le vérifierait mieux qu'une consigne — non écrit à ce jour. |
| `docs/etat-de-l-art.md` | Solutions voisines (Approov, Guardsquare, Truepic, C2PA, ProofMode) et ce qui distingue réellement ce dépôt. À relire avant tout arbitrage de feuille de route ; **daté**, revérifier les faits avant de s'en servir. |
| `docs/certification-anssi.md` | Piste de certification : pourquoi une cible de sécurité propre au produit plutôt qu'un profil de protection, et pourquoi elle ne remplace pas la piste réglementaire européenne de la spec §9. À relire avant tout arbitrage de feuille de route ; **daté**, revérifier référentiels et coûts avant de s'en servir. |

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
                  porte les sondes C3, C4.1 et C4.2. Le .xcodeproj et l'Info.plist
                  sont générés, non versionnés.
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
pytest              # 216 tests doivent passer
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

# Sonde A4.1 — boucle complète appareil → enveloppe → verdict, profil `core`.
# Elle remplace la sonde A5, dont elle est un sur-ensemble strict. Le numéro de
# projet Google Cloud est une donnée de compte, passée en propriété et jamais
# écrite dans le code. Le serveur de dev doit tourner sur l'hôte, et `adb reverse`
# évite d'avoir à relever une adresse IP ou à exposer le serveur au réseau.
# Serveur : DEPUIS LA RACINE DU DÉPÔT, autre terminal. Les chemins du `.env` y
# sont relatifs — lancé depuis `verifier-python/`, il ne trouve pas le fichier
# et retombe sur le substitut. Il l'annonce, mais l'annonce se perd si la
# sortie est redirigée sans `python -u`.
python -m probative.devserver --port 8765
adb reverse tcp:8765 tcp:8765
./gradlew :demo:installDebug -Pprobative.cloudProjectNumber=487335590129
adb logcat -c && adb shell am start -n org.probative.demo/.MainActivity
adb logcat -d -s PROBATIVE_A41
```

### iOS — appareil réel et compte payant requis pour App Attest

```bash
cd mobile/ios
swift test                        # 22 tests sur l'hôte, App Attest se saute
./scripts/make_xcframework.sh     # artefact autonome

# Projet Xcode, non versionné. L'adresse du serveur y entre par l'Info.plist :
# il n'existe pas d'`adb reverse` sur iOS, donc le serveur doit écouter sur le
# réseau local (`--host 0.0.0.0`) et l'iPhone partager le Wi-Fi du poste.
# `ruby` doit etre celui de Homebrew : le Ruby systeme (2.6) n'a pas le gem
# xcodeproj, et `gem install` y demanderait sudo.
PROBATIVE_DEVSERVER=http://$(ipconfig getifaddr en0):8765 \
  /opt/homebrew/opt/ruby/bin/ruby scripts/make_demo_project.rb

# Serveur : DEPUIS LA RACINE DU DÉPÔT, et sur le réseau local — l'iPhone ne
# voit pas la boucle locale du Mac, même relié en USB.
python -m probative.devserver --host 0.0.0.0 --port 8765

# Sondes : C4.2 (acquisition photo, profil `capture`) part au lancement ;
# C4.1 (profil `core`) et C3 (vecteur d'appareil) se choisissent à l'écran.
# Le préambule d'autorisations les demande toutes AVANT la première mesure,
# réseau local compris — la première campagne passe donc du premier coup.
# Une autorisation refusée ne se rattrape que dans Réglages › probative.

# Extraction par motif d'UUID : ~~awk '{print $3}'~~ tombait sur un mot du NOM
# de l'appareil dès qu'il contient des espaces (« iPhone 16 de Yannick »).
UDID=$(xcrun devicectl list devices \
  | grep -oE '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}' | head -1)
xcodebuild -project demo/ProbativeDemo.xcodeproj -scheme ProbativeDemo \
  -destination "id=$UDID" -derivedDataPath demo/build -allowProvisioningUpdates build
xcrun devicectl device install app --device "$UDID" \
  demo/build/Build/Products/Debug-iphoneos/ProbativeDemo.app
# Sans --console : ce drapeau attend la fin de l'application et donne
# l'impression que la commande est bloquée. Avec, lancer en arrière-plan et
# relire le journal — et non `timeout`, absent de macOS.
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
| Vérificateur Python, pipeline étapes 1–10 | Fonctionnel, 216 tests au vert |
| `AppAttestVerifier` — **phase D faite** | Attestation d'enrôlement validée **jusqu'à la racine publiée par Apple**, assertion validée par enveloppe. Éprouvé contre le vecteur iPhone 16 réel, 26 tests |
| `PlayIntegrityVerifier` — **phase B faite** | Jeton déchiffré par `decodeIntegrityToken`, `requestHash` recalculé et confronté, verdicts traduits. Chaîne d'attestation de clé ancrée à la racine Google (`key_attestation.py`). 35 tests |
| Vecteurs d'or | Trois jeux : `android`, `ios` (profil `capture`) et `core` (profil noyau). Reproduits octet à octet par Kotlin **et** Swift |
| Vecteurs d'appareil | Android (chaîne à 4 certificats, SM-X200) et iOS (App Attest, iPhone 16) versionnés dans `tests/device-vectors/` |
| Cœur natif Android | A1–A3 et **A5 faites, validées sur SM-X200**. **A4.1 écrite** — `seal(bytes)`, profil `core` : le cœur assemble et signe une enveloppe complète, épinglée au vecteur d'or par un test d'hôte. **Jamais exécutée sur appareil** : c'est la seule case qui reste pour le critère de sortie du spike. Puis A4.2, capture CameraX |
| Cœur natif iOS | C1–C3, **C4.1 et C4.2 faites** (iPhone 16, iOS 26.6, 2026-08-13). **Critère de sortie du spike atteint** en `core` (`STRONG`), puis **une photo réelle scellée** en `capture` : `STANDARD`, `integrity`/`position`/`time` au grade A, `origin` à B par le seul plafond de recapture — le maximum de la v0.1. Reste : chemin de production, chaînage |
| Liaisons Flutter / React Native | Non commencées. Couture, prévisualisation et commandes de prise de vue instruites dans `docs/acquisition-et-liaisons.md` — une décision y attend avant toute ligne de code |
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
  vaut exactement le R1 recalculé côté serveur.

  **Le chemin nominal a été exercé le même jour**, en publiant `org.probative.demo`
  sur une piste de test interne : `PLAY_RECOGNIZED`, `versionCode` attesté par Google,
  `LICENSED`, et les trois échelons d'intégrité cumulés. Voir
  `docs/play-integrity-service-account.md` §8, qui porte aussi les trois pièges de
  parcours — dont le **certificat de déploiement**, seul rapporté par le jeton et seul
  que la Play Console n'affiche pas.

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

### À faire en premier, dès qu'un appareil est branché

Les exécutions dues sur matériel réel sont notées ici et non dans un carnet
extérieur : ce dépôt est destiné à être repris, et un état de campagne qui ne
survit pas au poste ne vaut rien.

1. ~~**Rejouer C4.2 sur iPhone 16.**~~ **Fait le 2026-08-15.** Les correctifs de
   concurrence du 2026-08-13 — course de données dans `LocationDelegate`, délai
   de garde sur `Camera.capture` — ont tourné sur l'appareil. Résultat conforme
   à l'attendu : `STANDARD`, `position` en A avec `baro-consistent`, `origin` en
   B par le seul plafond de recapture, **aucun drapeau**, attestation réelle et
   non substitut.

   Un chiffre à surveiller : la capture a pris **2 494 ms** de temps mural,
   contre 1 904 ms le 2026-08-13, même appareil et même code. La variabilité
   entre deux exécutions identiques est elle-même l'information.

   ~~`media[6]` reste dans les clous, cette ligne incluant les 400 ms de
   convergence de session.~~ **Faux, corrigé le 2026-08-15 :** `shutterUptime`
   est estampillé dans `willCapturePhotoFor`, *après* `startRunning()` et après
   le délai de garde. Ni la mise sous tension du capteur ni les 400 ms n'entrent
   dans `media[6]` (`Sealer.swift`, `elapsed`). **Ces 2 494 ms ne sont donc pas
   ce qu'on compare aux 3 000 ms** de `max_sign_latency_ms`, et la marge réelle
   n'a jamais été lue — elle est plus large, d'un montant inconnu à ce jour.

   `Camera.capture` porte depuis une décomposition en six bornes
   (`CaptureTimings`), que la sonde imprime. Elle sépare ce qui est structurel
   et disparaîtrait avec un aperçu (mise sous tension), ce qui est en dur
   (garde), ce qui dépend de la scène (3A), et **le seul terme qui pèse dans
   `media[6]`** (encodage). La prochaine campagne rendra donc l'écart
   attribuable au lieu de le constater. Voir l'inconnue n° 2 et
   `docs/acquisition-et-liaisons.md` §2.
2. **Lancer A4.1 sur SM-X200.** Jamais exécutée sur matériel Android : la
   répétition du 2026-08-13 était sur émulateur, qui n'a ni clé matérielle ni
   verdict d'appareil. C'est ce qui manque pour établir le critère de sortie du
   spike côté Android — il l'est déjà côté iOS.

**Trois contraintes de poste, apprises à l'usage.** L'iPhone se reverrouille
entre deux campagnes et `devicectl` refuse alors de lancer (« Locked ») :
désactiver le verrouillage automatique sur l'appareil de test règle la question.
Le serveur de dev se lance **depuis la racine du dépôt**, sans quoi le `.env`
n'est pas trouvé et l'attestation retombe silencieusement sur le substitut. Et
`ipconfig getifaddr en0` ne rend **rien** sur le Mac mini, dont l'adresse est sur
`en1` — la commande de la section iOS suppose un poste où en0 est l'interface
active, ce qui n'est pas universel. Balayer les interfaces plutôt que présumer.

### Le cadre

**Spike d'attestation natif** — plan détaillé et phases dans
`docs/spike-attestation.md`. Cible précise : produire une enveloppe qu'un appareil
réel fait accepter par le vérificateur. **Atteinte le 2026-08-13 sur iPhone 16**
(C4.1, `STRONG`) ; reste à l'établir sur Android (A4.1) et à mettre une vraie photo
sous le sceau (A4.2/C4.2). `verifier-python/tests/factory.py` est l'implémentation
de référence — si le natif produit une enveloppe que la fabrique ne saurait pas
produire, c'est le natif qui s'écarte de la spécification.

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

1. **`requestHash` Play Integrity — close le 2026-08-12.** base64url sans bourrage :
   43 caractères pour un plafond de 500, aucun niveau d'indirection. L'aller-retour
   est vérifié — un jeton réel déchiffré par Google restitue un `requestHash`
   identique au R1 recalculé côté serveur. Une divergence d'encodage aurait cassé R1
   **silencieusement**, le pire mode de défaillance ; c'est écarté. *Reste* une
   formalité : rendre l'encodage normatif dans ADR-0002.
2. **Latence — levée le 2026-08-13 par C4.2.** La fraîcheur ne coûte rien
   (36–39 ms sur SM-X200, 18 ms sur iPhone 16) ; la **capture domine de deux
   ordres de grandeur** : 1 904 ms sur iPhone 16, scellement 49 ms.

   ~~Le seuil de 3 000 ms tient, mais la marge est mince.~~ **Confusion, levée le
   2026-08-15 :** ces 1 904 ms sont du temps mural de `capture()`, dont
   `media[6]` ne voit que la part **postérieure à l'obturateur**. On comparait à
   3 000 ms un nombre qui n'y entre pas. La marge n'est pas mince, elle est
   **non mesurée** — `CaptureTimings` la donne désormais.

   Ce qui reste vrai, et décisif, est l'ordonnancement du client : **la
   corroboration doit courir *pendant* l'acquisition**, faute de quoi elle entre
   bel et bien dans `media[6]` — elle, elle est en aval de l'obturateur — et fait
   accuser une latence anormale là où il n'y en a aucune (mesuré : +4,2 s). La
   jointure d'`acquire()` étant après l'obturateur, **tout capteur qui survit à
   la capture verse son excédent dans le champ noté** : c'est là qu'est la marge
   à surveiller, pas dans la durée de la photo. Reste à mesurer sur un appareil
   d'entrée de gamme, la SM-X200 étant la cible du pire cas.
3. **Chaînage Android** (spec §9) : inchangée, non instruite. La **série de captures**
   (`docs/acquisition-et-liaisons.md` §4) est le cas d'usage qui l'instruirait : une prise
   isolée n'a rien à chaîner, une série établit l'ordre et l'absence de retrait.
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
5. **Empreinte de bruit de capteur (PRNU)** — ouverte, cadrée par ADR-0007. Seule piste
   connue contre l'**injection de trames**, la faiblesse que la spec §2.5 reconnaît en
   écrivant que l'acquisition par le cœur « ne prouve pas l'origine capteur ». Elle se
   calculerait **côté serveur** à partir du payload, ce qui colle à l'invariant 1 sans
   rien demander de plus au client.

   Deux choses à ne pas reperdre. **Le PRNU ne répond pas à la recapture analogique** :
   photographier un écran avec l'appareil enrôlé produit un bruit parfaitement conforme.
   L'erreur a déjà été commise et corrigée une fois ; ADR-0007 point 6 la clôt. Et
   **aucun précédent commercial n'a été trouvé** — la revendication sur Truepic a été
   abaissée à confiance faible le 2026-08-15, faute de la moindre mention dans leur
   documentation publique.

   Trois mesures conditionnent tout engagement, dans cet ordre : ce que le pipeline
   computationnel laisse du résidu — un iPhone 16 débruite par réseau de neurones
   **avant** l'encodeur, et le résidu pourrait déjà être perdu, auquel cas seul le bayer
   RAW aurait un sens ; si la SM-X200 sait produire du DNG via Camera2 ; le coût en
   `media[6]` et en bande passante. Piste v0.3 : ne déplace ni A4.2, ni la phase B.
6. **Largeur d'encadrement du nonce contre drapeau `offline`** — ouverte le 2026-08-15,
   cadrée en spec §9, **moitié close le jour même**. Ce que le nonce établit est un
   encadrement bilatéral dont la largeur fait toute la valeur ; or `grade_time` ne
   consultait que `offline: bool`, et l'émission traite `ttl_ms` et `offline` comme deux
   entrées indépendantes. Le verdict suivait donc un mode déclaré, pas une grandeur
   mesurée.

   ~~**Fermer le cas « longue durée de vie déclarée en ligne » resserre**, aucun ADR
   nécessaire.~~ **Fait** : `max_nonce_window_ms` (15 min par défaut), plafond à C, deux
   tests. **Rouvrir le lot court à mieux que `DEGRADED` desserre** — ADR obligatoire, et
   c'est la moitié qui reste ouverte.

   Le point à ne pas reperdre, parce qu'il n'est pas celui qu'on pose d'instinct : la note
   porte sur la **largeur observée** — émission du nonce → jugement — et non sur `ttl_ms`.
   Un seuil sur la durée de vie déclarée aurait puni un lot consommé aussitôt, dont
   l'encadrement est pourtant serré, et c'est exactement l'erreur qu'on reprochait au
   drapeau. Un test épingle ce cas.

   Née de la question de la série de captures (`docs/acquisition-et-liaisons.md` §4), mais
   elle n'en dépend pas : le trou existait indépendamment de toute série. À noter que le
   lot ne débloquerait qu'iOS — côté Android, le jeton Play Integrity par enveloppe rend
   une série hors ligne impossible un pas plus loin.

### Deux chantiers ouverts, aucun bloqué

**Phase B — faite le 2026-08-12, à un câblage près.** Les trois réserves sont
tombées : racine Google confrontée, `requestHash` restitué intact et vérifié par
recalcul, jeton déchiffré. Le mode de déchiffrement a été **tranché par
contrainte** et non par préférence — les clés locales exigent une application
disponible sur Google Play, ce que la diffusion hors magasin ne permet pas. C'est
donc un appel à Google par enveloppe, avec ses quatre conséquences assumées
(`docs/play-integrity-service-account.md` §2), et l'authentification passe par la
couture d'ADR-0006 pour ne rien imposer aux déploiements.

~~*Reste à câbler* : la route d'enrôlement accepte encore la chaîne d'attestation
sans appeler `verify_key_attestation`.~~ **Câblé** : `/enroll` valide la chaîne
jusqu'à la racine Google, vérifie qu'elle porte bien sur la clé présentée, et en
tire `hardware_backed` — ce que le client déclare ne sert plus qu'au mode dégradé.

**A4.1 — l'enveloppe, écrite mais jamais exécutée sur matériel.** Le cœur Android
sait assembler et signer ; la sonde `:demo` enchaîne enrôlement, nonce, scellement
et verdict, et la boucle a tourné **sur émulateur**. Manque le seul geste qui
compte : brancher la SM-X200. ~~C'est ce qui coche le critère de sortie du spike~~
— **coché par C4.1 côté iOS le 2026-08-13** ; A4.1 reste nécessaire pour l'établir
sur Android, où la clé matérielle et le verdict d'appareil sont hors de portée d'un
émulateur.

~~**A4.2 / C4.2 — la capture.**~~ **C4.2 faite le 2026-08-13** : une photo réelle
est sous le sceau, en `STANDARD` — `origin` est bien retombé de A à B, comme prévu
et à raison. **A4.2 reste**, et c'est elle qui mesurera le pire cas : la SM-X200 est
un appareil d'entrée de gamme, là où l'iPhone 16 est le meilleur cas.

~~**Une convention d'unité à rendre normative**~~ — **fait le 2026-08-13**, spec
§2.4. Le trou était pire que prévu : la spec décrivait `baro-alt` comme une altitude
**relative** quand le vérificateur la confronte à `position[4]`, une altitude
**absolue**. Une valeur relative n'aurait jamais pu correspondre — et c'est
exactement ce qui fait prendre la mauvaise API sur iOS. Les unités sont désormais
normatives (`baro` en hPa, `baro-alt` en mètres absolus, accélérations en m/s²),
avec le corollaire qui compte : **une unité se corrige par un nouveau type, jamais
par redéfinition**, puisqu'un type inconnu est ignoré silencieusement là où un type
mal lu ne l'est pas.

### Ce que la phase D n'a pas couvert

~~Elle valide l'attestation et l'assertion **isolément**, jamais une enveloppe
complète de bout en bout.~~ **Comblé le 2026-08-13 par C4.1** : l'iPhone 16 a
produit un vrai `COSE_Sign1`, dont l'assertion porte le défi R1, et le pipeline l'a
jugé `STRONG`. La sonde C3 reste accessible dans la démonstration — elle seule
produit le vecteur d'appareil, qui se périme en trois jours.

Ce jalon vaut pour le chemin **développement** : l'`aaguid` est
`appattestdevelop`. Une compilation de distribution produit `appattest` et une
racine différente ; le serveur sait traiter les deux (`PROBATIVE_APPATTEST_ENV`),
mais **aucun vecteur de production n'existe**.

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
