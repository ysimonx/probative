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

## Documents de référence — à lire avant toute modification de fond

| Fichier | Rôle |
|---|---|
| `docs/architecture.html` | Vue d'ensemble illustrée du mécanisme, séquences et FAQ. Point d'entrée pour comprendre ; ne fait pas autorité. Les deux diagrammes de séquence sont générés par `tools/gen_sequences.py` — ne pas les éditer à la main. |
| `docs/threat-model.md` | Spécification de référence. Toute fonctionnalité doit répondre à une menace identifiée. |
| `docs/envelope-spec.md` | Format `probative/0.1`, noyau et profils (§2.5), règles de liaison R1/R2/R3, ordre de vérification |
| `docs/decisions/` | ADR. Les compléter plutôt que revenir silencieusement sur un choix. |
| `spec/envelope-v0.1.cddl` | Extrait de la spec, **ne pas éditer à la main** |
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
pytest              # 60 tests doivent passer
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
- Tout seuil de décision va dans les constantes en tête de `grading.py`, jamais en
  dur dans le code : ils seront recalibrés sur données réelles.
- Chaque test d'attaque référence la surface du modèle de menace (`test_s1_`, `test_s4_`…).
- Entrée hostile : décodage défensif via `Mapping` / `Sequence`, jamais `dict` / `list`
  (cbor2 en mode canonique restitue des types immuables).
- Aucun matériel cryptographique réel versionné. Voir `.gitignore`.

## État actuel

| Composant | État |
|---|---|
| Modèle de menace, spec d'enveloppe, ADR | Rédigés |
| Noyau et profils (ADR-0005) | **Fait de bout en bout** : spec §2.5, CDDL, vérificateur, vecteurs, et les deux cœurs natifs |
| Vérificateur Python, pipeline étapes 1–10 | Fonctionnel, 60 tests au vert |
| `PlayIntegrityVerifier`, `AppAttestVerifier` | Interfaces posées, `NotImplementedError`. **Vecteurs réels disponibles** — phases B et D n'ont plus d'excuse pour être écrites à l'aveugle |
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
  réseau. On a vérifié que la chaîne est cohérente, jamais que sa racine est
  bien **celle que Google publie**. Or une chaîne cohérente se fabrique de toutes
  pièces : sans confrontation à l'ancre, elle ne prouve rien.
- **Le jeton Play Integrity** est bien obtenu **auprès des serveurs de Google**,
  qui répondent. Mais il est **chiffré et n'a jamais été ouvert** : le lire exige
  de le faire déchiffrer par Google via un compte de service. **Obtenir un jeton
  n'est pas passer un contrôle** — le verdict qu'il contient dit très
  probablement que l'application n'est pas reconnue.

Idem côté iOS : l'objet App Attest est en main, sa cohérence interne vérifiée,
la signature d'Apple jamais. C'est exactement ce qu'apportent les phases B et D,
et pourquoi aucune ne peut être déclarée faite.

Et **aucune photo n'a encore été prise** : A4 et C4 restent à faire.

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

### Trois chantiers ouverts, aucun bloqué

**Phase B — `PlayIntegrityVerifier`.** Celle qui ferme le plus de réserves : la
racine Google jamais confrontée, l'aller-retour du `requestHash`, et le
déchiffrement du jeton. Elle dispose du vecteur Android réel. Demande un compte de
service Google pour l'API de déchiffrement.

**Phase D — `AppAttestVerifier`.** Symétrique, avec le vecteur App Attest en main.
Réserve connue : le vecteur est en environnement `appattestdevelop`, la production
utilise une autre racine.

**A4 / C4 — la capture.** La seule qui mettra enfin une photo sous le sceau, et le
vrai sujet de mesure de latence. Rien ne la bloque ; c'est aussi la plus longue.

Ordre suggéré : **B ou D d'abord**. Tant qu'aucun vérificateur ne juge, les preuves
collectées ne valent rien d'opposable, et A4 en produirait simplement davantage.

## Angle mort assumé

La **recapture analogique** n'est pas détectée en v0.1 : position authentique, attestation
valide, contenu faux. Photographier un écran et enregistrer un haut-parleur qui rejoue un
enregistrement sont la même attaque — d'où le nom, qui ne désigne plus un médium.

C'est pour cela que `origin` est plafonné au grade B **dans le profil `capture`**. Le
plafond ne s'applique pas au noyau, qui n'affirme rien sur le monde physique : depuis
ADR-0005, une enveloppe `core` peut atteindre `STRONG`. Ne pas lever le plafond sur
`capture` sans implémenter la détection.
