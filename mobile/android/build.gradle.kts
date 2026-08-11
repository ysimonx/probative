// Versions des plugins pour tous les modules. Le cœur (:core) doit rester
// publiable en AAR autonome, sans dépendance à un framework (ADR-0003).
plugins {
    id("com.android.library") version "8.10.1" apply false
    id("com.android.application") version "8.10.1" apply false
    id("org.jetbrains.kotlin.android") version "2.1.21" apply false
}
