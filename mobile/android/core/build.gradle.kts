import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.probative.core"
    compileSdk = 36

    defaultConfig {
        // StrongBox et l'API standard Play Integrity supposent de fait
        // un appareil récent ; 26 couvre setAttestationChallenge et les
        // horloges nécessaires. À réviser si un terrain plus ancien apparaît.
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
                "probative.vectors.dir",
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
    // Fraîcheur Play Integrity (règle R1). Seule dépendance d'exécution de
    // l'AAR : contrairement à DeviceCheck côté iOS, ce n'est pas un framework
    // système. C'est le seul chemin vers une attestation d'application sur
    // Android — assumé, et à ne pas laisser grossir.
    implementation("com.google.android.play:integrity:1.6.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.code.gson:gson:2.11.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
