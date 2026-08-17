import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Numéro de projet Google Cloud lié à l'application dans la Play Console.
// Fourni hors dépôt — c'est une donnée de compte, pas du code :
//   ./gradlew :demo:installDebug -Pprobative.cloudProjectNumber=123456789012
// Absent, la sonde le dit et saute l'étape Play Integrity plutôt que d'échouer
// sur un zéro silencieux.
val cloudProjectNumber = (findProperty("probative.cloudProjectNumber") as String?) ?: "0"

// Serveur de développement joignable depuis l'appareil. Le défaut suppose
// `adb reverse tcp:8765 tcp:8765`, préférable à une adresse IP : rien à
// relever, aucun réseau commun exigé, et le serveur reste sur la boucle
// locale de l'hôte plutôt qu'exposé au réseau.
//
//   ./gradlew :demo:installDebug -Pprobative.devserver=http://127.0.0.1:8765
val devserverUrl =
    (findProperty("probative.devserver") as String?) ?: "http://127.0.0.1:8765"

// Mode répétition — pour émulateur uniquement, et jamais par défaut.
//
//   ./gradlew :demo:installDebug -Pprobative.rehearsal=true
//
// Un émulateur ne produit qu'une clé logicielle : sa chaîne d'attestation est
// cohérente mais ne s'ancre à aucune racine publiée par Google, et le serveur
// la refuse — à raison. Ce drapeau enrôle alors la clé **sur parole**, ce qui
// n'atteste rien mais laisse exercer tout ce qui vient après : assemblage,
// R1, signature, verdict.
//
// Il ne dégrade jamais en silence : la sonde affiche une bannière, et le
// résultat obtenu sous ce drapeau ne vaut pas campagne.
val rehearsal = (findProperty("probative.rehearsal") as String?) == "true"

// Clé de téléversement Play — secret d'exploitation, hors dépôt.
//
// Lu depuis `mobile/android/keystore.properties`, **et non** depuis
// `~/.gradle/gradle.properties` : ce dernier vaut pour *tous* les projets
// Android de la machine, et une clé propre à `probative` n'a rien à y faire.
// Le fichier est ignoré par git ; en pratique c'est un lien symbolique vers
// le répertoire de secrets, comme `service-account.json` à la racine.
//
//   storeFile=/Users/…/secrets/probative/upload-keystore.jks
//   storePassword=…
//   keyAlias=upload
//   keyPassword=…
//
// Absent, `bundleRelease` produit un AAB **non signé**, que la Play Console
// refuse. C'est délibéré : mieux vaut un refus net qu'un artefact d'apparence
// valide signé par la clé de débogage.
//
// Attention : cette clé n'est PAS celle que Play Integrity rapportera. Play
// App Signing étant obligatoire pour toute application nouvelle, Google
// resigne les APK livrés avec une clé qu'il détient, et c'est *celle-là* que
// porte `certificateSha256Digest`. Voir docs/play-integrity-service-account.md.
val keystoreProperties = Properties().apply {
    val fichier = rootProject.file("keystore.properties")
    if (fichier.exists()) fichier.inputStream().use { load(it) }
}
val uploadStoreFile = keystoreProperties.getProperty("storeFile")

android {
    namespace = "org.probative.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.probative.demo"
        minSdk = 26
        targetSdk = 36
        versionCode = 12
        versionName = "0.2.1"
        buildConfigField("long", "CLOUD_PROJECT_NUMBER", "${cloudProjectNumber}L")
        buildConfigField("String", "DEVSERVER_URL", "\"$devserverUrl\"")
        buildConfigField("boolean", "REHEARSAL", "$rehearsal")
    }

    buildFeatures {
        buildConfig = true
    }

    signingConfigs {
        if (uploadStoreFile != null) {
            create("upload") {
                storeFile = file(uploadStoreFile)
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias") ?: "upload"
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Jamais de repli sur la configuration de débogage : un AAB signé
            // par la clé de débogage serait accepté par `adb install` et
            // refusé par Play, ce qui ferait perdre le temps de comprendre.
            signingConfig = signingConfigs.findByName("upload")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // La démonstration ne consomme que l'AAR. Si cette liste s'allonge au-delà
    // du cœur, c'est que du chemin critique a fui hors du cœur.
    implementation(project(":core"))

    // `ComponentActivity` pour son seul `LifecycleOwner`, qu'exige
    // `CaptureSession.open`. C'est la contrepartie d'ADR-0008 côté hôte : le
    // cœur décide *ce qui est lié*, l'application fournit la portée — et c'est
    // elle, pas lui, qui dépend d'AndroidX pour cela.
    //
    implementation("androidx.activity:activity:1.9.3")

    // `camera-view` pour le viseur — **ici et jamais dans `:core`**. C'est la
    // frontiere d'ADR-0008 rendue visible par une ligne de build : le coeur
    // possede la camera, l'application possede l'ecran. Un `PreviewView` dans
    // l'AAR ferait entrer `android.view` dans un artefact qui doit rester
    // autonome.
    implementation("androidx.camera:camera-view:1.4.2")
}
