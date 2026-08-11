# probative — coeur natif Android

Module `:core` publiable en AAR, plus une application `:demo` qui l'exerce sur appareil
reel. ADR-0003 : le coeur ne depend ni de Flutter ni de React Native, et tout le chemin
critique — capture, empreinte, defi R1, attestation, signature, assemblage CBOR — y reste.

## Prerequis

- JDK 17 (Temurin ou le JBR d'Android Studio). AGP 8.13 n'accepte pas moins.
- SDK Android : plateforme 36, build-tools 36.0.0.
- `local.properties` avec `sdk.dir=...`, non versionne. A defaut, `ANDROID_HOME`.

## Construire

```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home

./gradlew :core:assembleRelease     # -> core/build/outputs/aar/core-release.aar
./gradlew :demo:installDebug        # installe la demonstration sur l'appareil branche
```

## Verifier l'autonomie de l'AAR

C'est le critere ADR-0003, et il se controle — un `BUILD SUCCESSFUL` ne le prouve pas :

```bash
./gradlew :core:dependencies --configuration releaseRuntimeClasspath
```

Seul `org.jetbrains.kotlin:kotlin-stdlib` doit apparaitre. Toute autre ligne signifie
qu'une dependance vient de devenir transitive pour les consommateurs de l'AAR.

## Choix structurants

| Choix | Valeur | Motif |
|---|---|---|
| `minSdk` | 26 | Le CDD impose keystore materiel et attestation de cle aux appareils livres en 8.0+. En dessous, « signe par ce capteur » n'est plus adosse au materiel. |
| `compileSdk` / `targetSdk` | 36 | Palier exige par Google Play a partir d'aout 2026 ; une piste interne est necessaire pour Play Integrity. |
| Surface Kotlin | `explicitApi()` | Un AAR destine a la publication ne doit rien exposer qui n'ait ete concu comme contrat. |
| Dependances de `:core` | aucune | Voir ci-dessus. Les ajouts se justifient dans le plan du spike. |

## Etat

Etape A1 du spike (`docs/spike-attestation.md`) : squelette seulement. `:core` ne
contient que les constantes normatives de la specification. L'encodeur CBOR/COSE arrive
en A2, la cle materielle en A3, la capture en A4.
