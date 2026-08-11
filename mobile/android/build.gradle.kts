// Les greffons sont declares ici sans etre appliques : chaque module choisit les siens.

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
}
