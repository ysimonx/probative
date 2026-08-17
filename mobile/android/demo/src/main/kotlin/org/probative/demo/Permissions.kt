package org.probative.demo

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings

/**
 * Préambule d'autorisations — **tout est demandé avant la première mesure**.
 *
 * C'est la leçon de la campagne C4.2 côté iOS, transposée. Une autorisation
 * sollicitée au moment où le capteur sert affiche sa boîte de dialogue
 * *pendant* que le relevé court. Le symptôme ne nomme jamais la cause : un
 * délai qui expire ressemble à une panne de GPS, une corroboration absente
 * ressemble à un appareil sans baromètre.
 *
 * **La transposition n'est pas une copie, et l'écart est l'information.**
 * Android ne protège pas les mêmes choses qu'iOS :
 *
 * - **caméra** et **position** se demandent à l'exécution, comme sur iOS ;
 * - **le mouvement ne se demande pas.** Baromètre et accéléromètre sont
 *   librement lisibles ; seul le podomètre est protégé, par
 *   `ACTIVITY_RECOGNITION`. Là où iOS impose une autorisation unique pour
 *   tout le mouvement, Android n'en protège qu'une partie — et la part dont
 *   `position` tire sa corroboration barométrique n'en demande aucune ;
 * - **le réseau local n'existe pas** comme autorisation. `INTERNET` est
 *   accordée à l'installation, sans boîte de dialogue ni interface d'état.
 *   L'échec `-1009` qui a coûté des essais sur iPhone n'a pas d'équivalent.
 *
 * Ces lignes « non requise » sont affichées plutôt que masquées : c'est
 * l'invariant 4 appliqué à la démonstration — les deux plateformes atteignent
 * le même résultat par des chemins différents, et une liste commune qui
 * gommerait l'écart ferait croire à une symétrie qui n'existe pas.
 *
 * **Rien ne consomme encore ces autorisations** : le cœur Android n'a ni
 * caméra ni capteur, et la sonde A4.1 scelle des octets remis. Le préambule
 * existe pour qu'A4.2 démarre sur un appareil déjà autorisé, et pour que son
 * échec éventuel se lise du premier coup.
 */
internal class Permissions(private val activity: Activity) {

    /**
     * État d'une autorisation, tel qu'il s'affiche.
     *
     * `COARSE_ONLY` n'a pas d'équivalent iOS et mérite sa propre valeur :
     * depuis Android 12, la boîte de dialogue de position propose « précise »
     * ou « approximative ». Approximative est *accordée* — aucun refus, aucune
     * exception — mais la précision horizontale qui en sort dépasse largement
     * `max_h_accuracy_m`, et `position` sort en C. Confondre ce cas avec un
     * franc succès ferait chercher la dégradation partout sauf où elle est.
     */
    enum class State(val label: String, val symbol: String) {
        GRANTED("accordee", "✓"),
        COARSE_ONLY("approximative", "~"),
        UNDETERMINED("a demander", "?"),
        DENIED("refusee", "✗"),
        BLOCKED("refusee definitivement", "✗"),
        NOT_REQUIRED("non requise", "—"),
        ;

        /** Ce qui empêche une mesure, par opposition à ce qui la dégrade. */
        val blocking: Boolean get() = this == DENIED || this == BLOCKED
    }

    data class Entry(val label: String, val state: State, val note: String = "")

    private val prefs: SharedPreferences =
        activity.getSharedPreferences("probative-permissions", Activity.MODE_PRIVATE)

    /** Ce que la démonstration affiche, dans l'ordre du préambule iOS. */
    fun entries(): List<Entry> = listOf(
        Entry("camera", cameraState(), "A4.2"),
        Entry("position", locationState(), "A4.2"),
        Entry(
            "mouvement",
            State.NOT_REQUIRED,
            "barometre et accelerometre libres sur Android",
        ),
        Entry(
            "reseau",
            State.NOT_REQUIRED,
            "INTERNET accordee a l'installation",
        ),
    )

    /** Résumé sur une ligne — pour un journal lisible sans l'écran. */
    fun summary(): String =
        entries().joinToString(" ") { "${it.label} ${it.state.symbol}" }

    /** Reste-t-il une autorisation jamais soumise à l'utilisateur ? */
    fun needsRequest(): Boolean =
        entries().any { it.state == State.UNDETERMINED }

    /** Une autorisation refusée : la demande ne la rattrapera pas. */
    fun blocked(): Boolean = entries().any { it.state.blocking }

    /**
     * Prêt pour une acquisition. `COARSE_ONLY` passe : la capture aboutira, et
     * c'est au vérificateur de dégrader `position`, pas à la démonstration de
     * refuser de mesurer. Décider ici serait juger sur l'appareil.
     */
    fun readyForCapture(): Boolean =
        cameraState() == State.GRANTED &&
            locationState() in setOf(State.GRANTED, State.COARSE_ONLY)

    /**
     * Demande en une fois toutes les autorisations jamais soumises.
     *
     * Contrairement à iOS, la séquence n'a pas à être orchestrée : Android
     * enchaîne lui-même les boîtes de dialogue d'un même appel et ne jette pas
     * les demandes groupées.
     */
    fun request(requestCode: Int) {
        val manquantes = REQUESTABLE.filter { !isGranted(it) }
        if (manquantes.isEmpty()) return
        // Marqué **avant** l'appel : si l'utilisateur balaie la boîte de
        // dialogue sans répondre, la demande a tout de même eu lieu, et l'état
        // doit cesser d'être « à demander ». Sans cette trace, l'écran
        // proposerait indéfiniment un bouton qui n'affiche plus rien.
        manquantes.forEach { prefs.edit().putBoolean(it, true).apply() }
        activity.requestPermissions(manquantes.toTypedArray(), requestCode)
    }

    /**
     * Ouvre la fiche de l'application dans les Réglages.
     *
     * Pendant qu'iOS renvoie vers « Réglages › probative » par une phrase,
     * Android sait y conduire. Une autorisation définitivement refusée ne se
     * rattrape que là : proposer un bouton de demande qui n'afficherait plus
     * rien serait pire que de ne rien proposer.
     */
    fun openSettings() {
        activity.startActivity(
            Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", activity.packageName, null),
            ),
        )
    }

    // -- États ------------------------------------------------------------

    private fun cameraState(): State = stateOf(Manifest.permission.CAMERA)

    /**
     * La position se lit sur **deux** autorisations, jamais sur une.
     *
     * `ACCESS_FINE_LOCATION` refusée alors que `ACCESS_COARSE_LOCATION` est
     * accordée n'est pas un refus : c'est le choix « approximative » de la
     * boîte de dialogue. Ne regarder que la première afficherait « refusée »
     * sur un appareil qui rend pourtant des points.
     */
    private fun locationState(): State {
        val fine = stateOf(Manifest.permission.ACCESS_FINE_LOCATION)
        val coarse = stateOf(Manifest.permission.ACCESS_COARSE_LOCATION)
        return when {
            fine == State.GRANTED -> State.GRANTED
            coarse == State.GRANTED -> State.COARSE_ONLY
            else -> fine
        }
    }

    private fun isGranted(permission: String): Boolean =
        activity.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    /**
     * Distingue « jamais demandée » de « refusée définitivement ».
     *
     * Piège classique et sans contournement propre :
     * `shouldShowRequestPermissionRationale` rend `false` dans **les deux**
     * cas — avant toute demande, et après un refus définitif. Seule une trace
     * persistante de ce qui a déjà été demandé les sépare, d'où le
     * `SharedPreferences`. Les confondre afficherait « refusée
     * definitivement » sur une installation neuve.
     */
    private fun stateOf(permission: String): State = when {
        isGranted(permission) -> State.GRANTED
        !prefs.getBoolean(permission, false) -> State.UNDETERMINED
        activity.shouldShowRequestPermissionRationale(permission) -> State.DENIED
        else -> State.BLOCKED
    }

    private companion object {
        /**
         * Les seules autorisations que cette démonstration demandera jamais.
         *
         * `ACTIVITY_RECOGNITION` n'y figure pas : rien ne compte de pas, et
         * déclarer une autorisation qu'aucun code n'exerce est un ajout gratuit
         * que la Play Console relève. Elle viendra avec le podomètre, si le
         * podomètre vient.
         */
        val REQUESTABLE = listOf(
            Manifest.permission.CAMERA,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
        )
    }
}
