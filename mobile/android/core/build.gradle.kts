plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "org.probative.core"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            // Le coeur ne s'obscurcit pas lui-meme : c'est l'application consommatrice
            // qui decide de sa politique R8. `consumer-rules.pro` lui transmet ce qui
            // doit survivre.
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
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
    // Surface publique explicite : un AAR destine a etre publie ne doit pas exposer
    // par inadvertance ce qui n'a pas ete concu comme contrat.
    explicitApi()
}

// A1 volontairement sans dependance. Toute dependance ajoutee ici devient transitive
// pour les consommateurs de l'AAR -- ADR-0003, surface minimale.
dependencies {
}
