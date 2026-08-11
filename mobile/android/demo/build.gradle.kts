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

    buildTypes {
        release {
            isMinifyEnabled = false
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
