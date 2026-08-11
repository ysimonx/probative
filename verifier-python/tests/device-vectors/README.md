# Vecteurs d'appareil

Captures **réelles**, prises sur du matériel, par opposition aux vecteurs d'or
de `tests/vectors/` qui sont synthétiques et régénérés par
`tools/gen_vectors.py`. Rien ici n'est régénérable : ces octets sortent d'une
enclave et d'un service d'attestation, on ne les reproduit qu'en refaisant la
manipulation sur l'appareil.

Ils existent pour une raison précise : écrire `AppAttestVerifier` sans jamais
avoir vu une attestation Apple authentique reviendrait à coder contre une
documentation. Le dépôt s'est déjà donné cette règle côté Android — le vecteur
d'appareil est ce qui permet de la tenir côté iOS.

> Aucune clé privée. Ce qui est publié, ce sont des certificats d'attestation,
> un reçu signé par Apple et des données publiques d'authentificateur. Le
> `.gitignore` interdit le matériel cryptographique réel : il s'agit de secrets,
> pas de preuves publiques.

## `keystore-a3-sm-x200.json` — Android

| | |
|---|---|
| Origine | Samsung SM-X200, Android 14, patch de sécurité 2025-08-01 |
| Produit par | `KeystoreVectorDeviceTest`, étape A3 du spike |
| Date | 2026-08-11 |
| Niveau | `TRUSTED_ENVIRONMENT` — cet appareil n'expose pas StrongBox |

Chaîne d'attestation de clé à **4 certificats**, clé publique X9.62, `kid`, une
signature de contrôle, et le défi d'attestation avec ses composants.

Le défi est un **vrai R1**, `SHA-256(payload ‖ nonce)`. C'est ce qui rend le
vecteur intéressant : Keymaster recopie ce défi dans l'extension d'attestation
`1.3.6.1.4.1.11129.2.1.17` du certificat feuille, donc un vérificateur peut
retrouver la liaison **par recalcul** au lieu de croire le client.

### Ce qui a été vérifié à la capture

Tout ceci a été refait à la main sur le vecteur, avant de le figer — un vecteur
qu'on n'a pas su vérifier soi-même ne vaut rien comme référence :

- défi inscrit par le TEE dans l'extension == `SHA-256(payload ‖ nonce)` recalculé ;
- `attestationSecurityLevel` = `TrustedEnvironment` **dans l'attestation**, et pas
  seulement d'après ce que déclare l'appareil (`attestationVersion` = 3) ;
- les 4 certificats s'enchaînent, chaque signature vérifiée, racine auto-signée ;
- clé publique du certificat feuille == clé exportée par le cœur ;
- `kid` == `SHA-256(clé publique X9.62)` ;
- signature `r‖s` de contrôle acceptée par la clé attestée.

Empreinte SHA-256 de la racine :
`1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc`

### Ce qu'il ne prouve pas

La racine **n'a pas été confrontée à la racine d'attestation matérielle publiée
par Google**, ni aucun certificat à une liste de révocation : c'est le cœur de la
phase B. Une chaîne cohérente avec elle-même reste une chaîne que n'importe qui
peut fabriquer — seule l'ancre de confiance la rend opposable.

StrongBox n'est pas exercé, faute d'appareil au banc qui l'expose. Et Play
Integrity — le pendant réel d'App Attest, qui atteste l'*application* et non la
clé — n'est pas dans ce vecteur : c'est l'étape A5, non commencée.

### Refaire la capture

```bash
cd mobile/android
adb logcat -c
./gradlew :core:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.probative.core.keys.KeystoreVectorDeviceTest
adb logcat -d -s PROBATIVE_VECTOR   # tronçons numérotés à recoller
```

Le vecteur sort par **logcat**, pas par un fichier. Gradle désinstalle le paquet
de test à la fin de la campagne, ce qui emporte son répertoire de données ; et
depuis Android 11, `adb` ne peut plus lire `Android/data` d'une autre
application. Le tampon logcat survit aux deux. Les tronçons sont numérotés parce
que l'ordre de lecture du tampon n'est pas garanti.

Chaque exécution génère une clé neuve : `kid`, certificats et défi diffèrent
d'une capture à l'autre. Un test ne doit jamais coder ces valeurs en dur.

## `appattest-c3-iphone16.json` — iOS

| | |
|---|---|
| Origine | iPhone 16 (iPhone17,3), iOS 26.6 |
| Application | `org.probative.demo`, équipe `9SGKL7VUD3` |
| Produit par | `mobile/ios/demo`, étape C3 du spike |
| Date | 2026-08-11 |
| Environnement | **`appattestdevelop`** — build de développement |

Le fichier porte, en base64 : l'objet d'attestation d'enrôlement (5 816 octets,
`fmt = apple-appattest`, chaîne `x5c` à deux certificats, reçu de 3 966 octets),
une assertion de capture (142 octets), la clé d'enveloppe Secure Enclave
(publique X9.62 et `kid`), et les latences mesurées.

Le défi d'enrôlement, la charge utile et le nonce sont inclus **en clair**.
C'est délibéré : sans eux le vérificateur ne peut pas recalculer
`clientDataHash`, et un test qui ne recalcule pas la liaison ne teste pas la
liaison. Le `clientDataHash` de l'assertion vaut le défi R1,
`SHA-256(payload_bytes ‖ nonce)` — la règle R1 est vérifiable sur ce vecteur.

### Ce qu'il permet de vérifier

- chaîne `x5c` jusqu'à la racine App Attest d'Apple ;
- `rpIdHash == SHA-256("9SGKL7VUD3.org.probative.demo")` ;
- `credentialId == keyId` ;
- compteur d'assertion : 0 à l'enrôlement, 1 à la première assertion ;
- liaison R1 de l'assertion, par recalcul.

### Ce qu'il ne prouve pas

L'environnement est celui de développement. Un build de distribution produit
`appattestprod` et une **racine différente** : un vérificateur qui ne passerait
que sur ce vecteur ne serait pas prêt pour la production. Le compteur ne couvre
qu'un seul incrément, donc pas le rejeu ni le recul — ces cas se construisent
par mutation du vecteur, en test.

### Refaire la capture

```bash
cd mobile/ios
ruby scripts/make_demo_project.rb
xcodebuild -project demo/ProbativeDemo.xcodeproj -scheme ProbativeDemo \
  -destination "id=<UDID>" -derivedDataPath demo/build -allowProvisioningUpdates build
xcrun devicectl device install app --device <UDID> \
  demo/build/Build/Products/Debug-iphoneos/ProbativeDemo.app
xcrun devicectl device process launch --device <UDID> --terminate-existing org.probative.demo
xcrun devicectl device copy from --device <UDID> \
  --domain-type appDataContainer --domain-identifier org.probative.demo \
  --source Documents/c3-fixture.json --destination ./c3-fixture.json
```

`generateKey` crée une clé App Attest neuve à chaque exécution : le `keyId`, les
certificats et le compteur diffèrent d'une capture à l'autre. C'est normal, et
c'est pourquoi un test ne doit jamais coder ces valeurs en dur.
