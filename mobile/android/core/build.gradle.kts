import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.attestedcapture.core"
    compileSdk = 36

    defaultConfig {
        // StrongBox et l'API standard Play Integrity supposent de fait
        // un appareil récent ; 26 couvre setAttestationChallenge et les
        // horloges nécessaires. À réviser si un terrain plus ancien apparaît.
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.all {
            // Les vecteurs d'or vivent dans le vérificateur : source unique,
            // aucune copie à faire dériver.
            it.systemProperty(
                "ac.vectors.dir",
                rootDir.resolve("../../verifier-python/tests/vectors").canonicalPath,
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.code.gson:gson:2.11.0")
}
