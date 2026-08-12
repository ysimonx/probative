package org.probative.core.payload

import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.SystemClock
import android.provider.Settings
import java.util.TimeZone

/**
 * Collecte des blocs `timing` et `posture` — la part du noyau qui touche
 * l'appareil.
 *
 * **Aucune permission d'exécution n'est requise ici**, et c'est délibéré :
 * sceller des octets remis ne doit coûter ni caméra ni position. Ce qui
 * exige une permission relève de l'acquisition, donc du profil `capture`.
 *
 * Rien n'est jugé : ces valeurs partent telles quelles au serveur
 * (invariant 1). Un client compromis peut toutes les mentir, et c'est
 * précisément pourquoi elles ne pèsent presque rien dans la notation.
 */
object DeviceState {

    /**
     * Les trois horloges au moment de l'appel.
     *
     * Le décalage UTC est calculé pour l'instant courant, pas pour le fuseau
     * « en général » : un fuseau à heure d'été rendrait sinon une valeur
     * fausse la moitié de l'année.
     */
    fun timing(context: Context): Timing {
        val wallMs = System.currentTimeMillis()
        return Timing(
            wallMs = wallMs,
            elapsedRealtimeMs = SystemClock.elapsedRealtime(),
            utcOffsetMinutes = TimeZone.getDefault().getOffset(wallMs) / 60_000,
            automaticTime = globalFlag(context, Settings.Global.AUTO_TIME),
        )
    }

    /**
     * L'état déclaré de l'appareil. [appVersion] vient de l'intégrateur : le
     * cœur ne connaît pas le `BuildConfig` de l'application qui l'embarque.
     *
     * Deux champs restent **omis** à ce stade, et l'omission est le
     * comportement correct — pas un manque à combler par une valeur par
     * défaut :
     *
     * - l'indicateur de position simulée (label 7) ne se lit que sur un point
     *   de localisation, qu'un scellement d'octets remis n'a pas ;
     * - la liste de paquets suspects (label 8) suppose une énumération des
     *   paquets installés, soumise à `QUERY_ALL_PACKAGES` depuis Android 11.
     *
     * Les deux arriveront avec l'acquisition (A4.2/A6), qui les paie déjà.
     */
    fun posture(context: Context, appVersion: String): Posture = Posture(
        platform = "android",
        osVersion = Build.VERSION.RELEASE ?: Build.VERSION.SDK_INT.toString(),
        appVersion = appVersion,
        debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger(),
        emulatorSuspected = emulatorSuspected(),
        developerMode = globalFlag(context, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
    )

    /**
     * Réglage global à trois états : activé, désactivé, **jamais écrit**.
     *
     * `Settings.Global.getInt` avec valeur par défaut écrase le troisième
     * cas en « désactivé ». On lit donc la chaîne brute, et l'absence
     * remonte en `null` jusqu'à l'omission du champ.
     */
    private fun globalFlag(context: Context, name: String): Boolean? =
        Settings.Global.getString(context.contentResolver, name)?.let { it.trim() == "1" }

    /**
     * Faisceau d'indices d'émulateur, **volontairement grossier**.
     *
     * Un émulateur déterminé efface ces traces en une ligne de `ro.build.*` :
     * ce champ n'est donc pas une défense. La défense est Play Integrity, qui
     * répond `MEETS_VIRTUAL_INTEGRITY` sans que l'appareil ait son mot à dire.
     * Ce booléen ne sert qu'à rendre lisible le cas ordinaire — une campagne
     * lancée par erreur sur un émulateur de développement.
     */
    private fun emulatorSuspected(): Boolean {
        val empreinte = Build.FINGERPRINT
        return empreinte.startsWith("generic") ||
            empreinte.startsWith("unknown") ||
            empreinte.contains("test-keys") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
            Build.PRODUCT == "google_sdk" ||
            Build.HARDWARE == "goldfish" ||
            Build.HARDWARE == "ranchu"
    }
}
