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
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("long", "CLOUD_PROJECT_NUMBER", "${cloudProjectNumber}L")
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
}
