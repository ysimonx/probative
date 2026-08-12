package org.probative.demo

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.util.TypedValue
import android.widget.ScrollView
import android.widget.TextView
import java.security.MessageDigest
import kotlin.concurrent.thread
import org.probative.core.freshness.PlayIntegrity
import org.probative.core.keys.KeystoreKeys

/**
 * Écran unique de la démonstration — sonde A5, pendant Android de la sonde C3
 * (`mobile/ios/demo`).
 *
 * Elle ne juge rien (invariant 1) : elle collecte une clé matérielle et un
 * jeton Play Integrity, et rapporte des tailles et des latences. Le jeton part
 * opaque ; sa validation est la phase B.
 *
 * Pas de fichier de ressources ni de bibliothèque d'interface : la
 * démonstration doit rester assez pauvre pour qu'on ne soit jamais tenté d'y
 * loger de la logique qui appartient au cœur.
 */
public class MainActivity : Activity() {

    private companion object {
        const val TAG = "PROBATIVE_A5"
    }

    private lateinit var view: TextView
    private val lines = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        view = TextView(this).apply {
            setTextIsSelectable(true)
            setPadding(48, 96, 48, 48)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        setContentView(ScrollView(this).apply { addView(view) })

        // Play Integrity et Keystore bloquent : jamais sur le fil principal.
        thread { probe() }
    }

    private fun report(text: String) {
        Log.i(TAG, text)
        lines.appendLine(text)
        Handler(Looper.getMainLooper()).post { view.text = lines }
    }

    private fun probe() {
        report("probative — sonde A5")
        report("")

        // Défi R1 : SHA-256(payload ‖ nonce). Charge utile de substitution,
        // la capture réelle est l'étape A4.
        val payload = "charge utile de substitution — sonde A5".toByteArray()
        val nonce = ByteArray(16) { ((it * 7) + 3).toByte() }
        val challenge = MessageDigest.getInstance("SHA-256").digest(payload + nonce)
        report("defi R1        ${challenge.size} octets")

        // ── Clé matérielle ────────────────────────────────────────────────
        val alias = "probative-demo-${System.currentTimeMillis()}"
        try {
            val start = System.nanoTime()
            KeystoreKeys.generate(alias, challenge)
            val ms = (System.nanoTime() - start) / 1_000_000.0
            report("cle materielle ${KeystoreKeys.securityLevel(alias)} en %.0f ms".format(ms))
            report("kid            ${b64(KeystoreKeys.kid(alias))}")
            report("chaine         ${KeystoreKeys.certificateChain(alias).size} certificats")
        } catch (e: Exception) {
            report("ECHEC cle      ${e.javaClass.simpleName} ${e.message}")
        }

        // ── Encodage du requestHash (inconnue n° 1) ───────────────────────
        val requestHash = PlayIntegrity.encodeRequestHash(challenge)
        report("")
        report("requestHash    ${requestHash.length} caracteres " +
            "(plafond ${PlayIntegrity.MAX_REQUEST_HASH_LENGTH})")
        report("               $requestHash")

        // ── Play Integrity ────────────────────────────────────────────────
        val cloudProjectNumber = BuildConfig.CLOUD_PROJECT_NUMBER
        if (cloudProjectNumber <= 0L) {
            report("")
            report("Play Integrity SAUTE — numero de projet Google Cloud absent.")
            report("  relancer avec -Pprobative.cloudProjectNumber=<numero>")
            return
        }

        try {
            report("")
            report("projet cloud   $cloudProjectNumber")
            var start = System.nanoTime()
            val provider = PlayIntegrity.prepare(this, cloudProjectNumber)
            report("prepare        %.0f ms".format((System.nanoTime() - start) / 1_000_000.0))

            start = System.nanoTime()
            val token = PlayIntegrity.token(provider, challenge)
            val ms = (System.nanoTime() - start) / 1_000_000.0
            report("jeton          ${token.length} caracteres en %.0f ms".format(ms))
            // Le jeton part au serveur tel quel : on ne le lit jamais ici.
            //
            // Il sort en tronçons numérotés, comme le vecteur d'attestation de
            // clé : logcat tronque les lignes longues, et un jeton coupé en
            // silence ferait échouer le déchiffrement sans dire pourquoi. Ce
            // n'est pas du confort — c'est le seul moyen de faire parvenir un
            // jeton entier au poste de développement pour la phase B.
            token.chunked(160).forEachIndexed { i, part ->
                report("jeton[$i]       $part")
            }
            report("jeton fin      ${token.length} caracteres au total")
        } catch (e: Exception) {
            // Le message d'erreur porte le code Play Integrity, seul moyen de
            // distinguer « application inconnue de Play » d'un vrai échec.
            report("ECHEC integrity ${e.javaClass.simpleName}")
            report("  ${e.cause?.message ?: e.message}")
        } finally {
            if (KeystoreKeys.exists(alias)) KeystoreKeys.delete(alias)
        }
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
}
