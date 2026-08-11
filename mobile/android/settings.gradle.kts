// Projet Gradle du coeur natif Android.
//
// ADR-0003 : `:core` doit produire un AAR consommable seul, sans dependance a Flutter
// ni a React Native. `:demo` n'existe que pour exercer cet AAR sur appareil reel ; il
// n'est jamais publie et rien dans `:core` ne doit dependre de lui.

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    // Un depot declare dans un module serait invisible ici : on interdit la pratique
    // pour que la provenance des artefacts reste lisible en un seul endroit.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "probative-android"

include(":core")
include(":demo")
