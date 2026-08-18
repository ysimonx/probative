package org.probative.demo

import android.content.Context
import android.content.SharedPreferences

/**
 * Ce qui doit survivre à la mort du processus — et rien d'autre.
 *
 * **Deux états y sont contraints, et pour la même raison.** Depuis qu'une
 * visite est la chaîne (ADR-0009, amendement « la visite »), une visite de
 * plusieurs heures verra probablement plusieurs processus : Android tue une
 * application en arrière-plan sous pression mémoire, et rien ne l'en empêche.
 * Ce qui ne survit pas au processus ne survit donc pas à la visite.
 *
 * - **L'alias de la clé enrôlée.** L'enrôlement est un événement
 *   d'*installation*, jamais de capture ni de lancement. Un alias neuf donne
 *   une clé neuve, donc un `kid` neuf, donc un appareil neuf pour le serveur —
 *   et la chaîne repart d'une tête à chaque relance. C'est la même erreur que
 *   celle corrigée le 2026-08-17 au niveau de la capture, d'un cran au-dessus,
 *   et son symptôme est le même : `CHAIN_FIRST_LINK_UNKNOWN`.
 * - **L'état de la visite** — dernier condensat, numéro, compteur, instant
 *   d'ouverture. Sans lui la chaîne se rompt là où l'utilisateur n'a rien fait.
 *
 * Ce qui n'y est **pas**, à dessein : le fournisseur Play Integrity, qui n'a
 * aucune forme sérialisée et ne peut donc pas y entrer ; et l'historique des
 * prises, qui appartient à l'écran, pas à la preuve.
 */
class Persistance(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("probative-etat", Context.MODE_PRIVATE)

    var alias: String?
        get() = prefs.getString(ALIAS, null)
        set(value) = prefs.edit().apply {
            if (value == null) remove(ALIAS) else putString(ALIAS, value)
        }.apply()

    /** Condensat en hexadécimal : `SharedPreferences` ne stocke pas d'octets. */
    var dernierDigest: ByteArray?
        get() = prefs.getString(DIGEST, null)?.let { hex ->
            ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }
        set(value) = prefs.edit().apply {
            if (value == null) remove(DIGEST)
            else putString(DIGEST, value.joinToString("") { "%02x".format(it) })
        }.apply()

    var visite: Int
        get() = prefs.getInt(VISITE, 1)
        set(value) = prefs.edit().putInt(VISITE, value).apply()

    var prises: Int
        get() = prefs.getInt(PRISES, 0)
        set(value) = prefs.edit().putInt(PRISES, value).apply()

    var debutMs: Long
        get() = prefs.getLong(DEBUT, 0L)
        set(value) = prefs.edit().putLong(DEBUT, value).apply()

    private companion object {
        const val ALIAS = "alias"
        const val DIGEST = "dernier-digest"
        const val VISITE = "visite"
        const val PRISES = "prises"
        const val DEBUT = "debut-ms"
    }
}
