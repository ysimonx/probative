package org.probative.demo

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.util.TypedValue
import android.view.WindowInsets
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread
import org.json.JSONObject
import org.probative.core.envelope.Sealer
import org.probative.core.freshness.PlayIntegrity
import org.probative.core.freshness.PlayIntegrityFreshness
import org.probative.core.keys.KeystoreKeys
import org.probative.core.payload.CorePayload

/**
 * Écran unique de la démonstration — sonde **A4.1** : la boucle complète
 * « appareil → enveloppe → verdict serveur », profil `core`, sans caméra.
 *
 * Elle remplace la sonde A5, qui s'arrêtait au jeton Play Integrity : la
 * séquence ci-dessous en est un sur-ensemble strict — clé matérielle, jeton
 * lié au défi R1, et cette fois l'enveloppe signée qui va au bout.
 *
 * Elle ne juge rien (invariant 1). Le seul verdict affiché est celui que le
 * serveur renvoie ; rien ici ne le calcule, ne l'anticipe ni ne le résume.
 *
 * Pas de fichier de ressources ni de bibliothèque d'interface : la
 * démonstration doit rester assez pauvre pour qu'on ne soit jamais tenté d'y
 * loger de la logique qui appartient au cœur.
 */
public class MainActivity : Activity() {

    private companion object {
        const val TAG = "PROBATIVE_A41"

        /** Identifiant de déploiement — celui des vecteurs, pour un dev server. */
        const val DEPLOYMENT = "test-deployment"

        /**
         * Les octets à sceller. N'importe lesquels feraient l'affaire : le
         * noyau n'affirme rien de leur provenance, et c'est exactement ce que
         * cette étape doit montrer.
         */
        val CONTENT = "probative — octets remis au scellement, sonde A4.1\n"
            .toByteArray(Charsets.UTF_8)
        const val CONTENT_TYPE = "text/plain"
    }

    private lateinit var view: TextView
    private val lines = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // L'identité du binaire est **épinglée hors du défilement**, et ce
        // n'est pas de la mise en page : au fil du journal, elle finissait
        // poussée hors champ par le verdict qui s'affiche après elle. Un
        // lecteur voyait alors le résultat sans savoir quelle version l'avait
        // produit — le piège qu'A5 avait identifié sur une campagne à
        // plusieurs versions.
        //
        // L'épinglage ne suffisait pas : la vraie cause de la disparition
        // observée était le bord à bord, traité plus bas.
        val header = TextView(this).apply {
            setPadding(48, 96, 48, 24)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            text = identity()
        }
        view = TextView(this).apply {
            setTextIsSelectable(true)
            setPadding(48, 0, 48, 48)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(header, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(
                ScrollView(this@MainActivity).apply { addView(view) },
                LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f),
            )
        }

        // Depuis `targetSdk 35`, l'affichage bord à bord est imposé : la fenêtre
        // occupe l'écran entier et le contenu se dessine **sous** la barre d'état
        // et la barre de navigation. Sans ce recul, les premières lignes — donc
        // l'identité du binaire — sont masquées par la barre système, ce qui
        // ressemble à s'y méprendre à un défilement.
        root.setOnApplyWindowInsetsListener { v, insets ->
            val bars = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val i = insets.getInsets(WindowInsets.Type.systemBars())
                intArrayOf(i.left, i.top, i.right, i.bottom)
            } else {
                @Suppress("DEPRECATION")
                intArrayOf(
                    insets.systemWindowInsetLeft,
                    insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight,
                    insets.systemWindowInsetBottom,
                )
            }
            v.setPadding(bars[0], bars[1], bars[2], bars[3])
            insets
        }
        setContentView(root)

        // Play Integrity, Keystore et le réseau bloquent : jamais sur le fil
        // principal.
        thread { probe() }
    }

    /**
     * Ce qui identifie le binaire et ce qu'il vaut — toujours à l'écran.
     *
     * L'installateur y figure pour la même raison que la version :
     * `com.android.vending` distingue une installation Play d'un `adb install`,
     * et les deux ne portent pas la même signature, donc pas la même empreinte
     * de certificat — ce qui change le verdict `origin` du tout au tout.
     */
    private fun identity(): String = buildString {
        appendLine("probative — sonde A4.1 : enveloppe complete, profil core")
        appendLine(
            "version ${BuildConfig.VERSION_NAME} (code ${BuildConfig.VERSION_CODE})" +
                " — installee par ${installerName()}",
        )
        append("serveur ${BuildConfig.DEVSERVER_URL}")
        if (BuildConfig.REHEARSAL) {
            // Épinglé, et non journalisé : un résultat obtenu sous ce drapeau
            // n'atteste rien, et doit rester illisible autrement.
            appendLine()
            appendLine()
            appendLine("*** REPETITION — cle enrolee SUR PAROLE, sans attestation.")
            append("*** Exerce la plomberie, ne vaut pas campagne.")
        }
    }

    /** Qui a installé ce binaire — `com.android.vending` pour le Play Store. */
    private fun installerName(): String {
        val nom = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }
        return nom ?: "adb / inconnu"
    }

    private fun report(text: String) {
        Log.i(TAG, text)
        lines.appendLine(text)
        Handler(Looper.getMainLooper()).post { view.text = lines }
    }

    private fun probe() {
        // L'identité du binaire est à l'écran en permanence (`identity`) ; ici
        // on ne la journalise qu'une fois, parce que logcat n'a pas d'en-tête
        // épinglé et qu'un extrait de journal sans version ne vaut rien.
        Log.i(TAG, identity())

        val cloudProjectNumber = BuildConfig.CLOUD_PROJECT_NUMBER
        if (cloudProjectNumber <= 0L) {
            // Sans jeton, l'enveloppe n'aurait pas de preuve de fraîcheur :
            // il n'y a pas de version dégradée de cette sonde.
            report("ARRET — numero de projet Google Cloud absent.")
            report("  reconstruire avec -Pprobative.cloudProjectNumber=<numero>")
            return
        }

        val alias = "probative-a41-${System.currentTimeMillis()}"
        try {
            sequence(alias, cloudProjectNumber)
        } catch (e: DevServer.Refused) {
            report("ECHEC serveur  HTTP ${e.status}")
            report("  ${e.detail}")
        } catch (e: Exception) {
            report("ECHEC          ${e.javaClass.simpleName}")
            report("  ${e.cause?.message ?: e.message}")
        } finally {
            if (KeystoreKeys.exists(alias)) KeystoreKeys.delete(alias)
        }
    }

    /** Les cinq temps de la boucle, dans l'ordre où le format les impose. */
    private fun sequence(alias: String, cloudProjectNumber: Long) {
        val server = DevServer(BuildConfig.DEVSERVER_URL)

        // ── 1. Fournisseur Play Integrity ─────────────────────────────────
        //
        // Au démarrage, jamais sur le chemin du scellement : `prepare` coûte
        // deux ordres de grandeur de plus qu'une demande de jeton (1 313 ms
        // contre 36–39 ms, SM-X200, 2026-08-11).
        report("projet cloud   $cloudProjectNumber")
        var start = System.nanoTime()
        val provider = PlayIntegrity.prepare(this, cloudProjectNumber)
        report("prepare        %.0f ms".format(ms(start)))

        // ── 2. Clé matérielle et enrôlement ───────────────────────────────
        //
        // Le défi d'enrôlement doit survivre à la génération : le serveur le
        // confronte à celui que le TEE a inscrit dans l'extension
        // d'attestation. Le perdre rendrait la chaîne invérifiable.
        val enrollChallenge = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        start = System.nanoTime()
        KeystoreKeys.generate(alias, enrollChallenge)
        report("cle materielle ${KeystoreKeys.securityLevel(alias)} en %.0f ms".format(ms(start)))

        val chain = KeystoreKeys.certificateChain(alias)
        // En répétition, la chaîne n'est pas transmise : celle d'un émulateur
        // est cohérente mais ne s'ancre à aucune racine Google, et le serveur
        // la refuse — à raison. On enrôle alors sur parole pour exercer la
        // suite, et la bannière ci-dessus dit ce que le résultat ne vaut pas.
        val enrolled = server.enroll(
            KeystoreKeys.publicKeyX962(alias),
            if (BuildConfig.REHEARSAL) null else chain,
            enrollChallenge,
        )
        report("enrolement     ${chain.size} certificats, kid ${enrolled.getString("kid_hex")}")
        // `attested: false` signifie que la clé a été acceptée sur parole — le
        // mode dégradé du serveur de dev, qui ne prouve rien.
        report("               chaine attestee : ${enrolled.getBoolean("attested")}")

        // ── 3. Nonce, émis pour le profil ─────────────────────────────────
        val issued = server.nonce(KeystoreKeys.kid(alias), CorePayload.PROFILE)
        val nonce = Base64.decode(issued.getString("nonce_b64"), Base64.NO_WRAP)
        val profile = issued.getString("profile")
        report("")
        report("nonce          ${nonce.size} octets, profil $profile, ttl ${issued.getInt("ttl_ms")} ms")
        // Le profil signé doit être celui du nonce. `Sealer` produit `core` :
        // si le serveur en a demandé un autre, mieux vaut s'arrêter ici que
        // faire signer une enveloppe qu'il rejettera pour cette raison.
        check(profile == CorePayload.PROFILE) {
            "le serveur a emis un nonce pour le profil $profile, ce sceau produit " +
                "${CorePayload.PROFILE}"
        }

        // ── 4. Scellement ─────────────────────────────────────────────────
        val sealer = Sealer(
            context = this,
            deployment = DEPLOYMENT,
            keyAlias = alias,
            appVersion = BuildConfig.VERSION_NAME,
            freshness = PlayIntegrityFreshness(provider),
        )
        start = System.nanoTime()
        val sealed = sealer.seal(CONTENT, CONTENT_TYPE, nonce)
        report("")
        report("scellement     %.0f ms".format(ms(start)))
        report("charge utile   ${sealed.payloadBytes.size} octets")
        report("defi R1        ${b64(sealed.challenge)}")
        report("enveloppe      ${sealed.bytes.size} octets")

        // ── 5. Verdict ────────────────────────────────────────────────────
        start = System.nanoTime()
        val result = server.verify(sealed.bytes, CONTENT)
        report("verification   %.0f ms".format(ms(start)))
        report("")
        reportResult(result)
    }

    /**
     * Le résultat, propriété par propriété. Ni `level` seul, ni résumé
     * maison : le format de sortie du vérificateur est structuré pour une
     * raison, et un affichage qui l'aplatirait ferait perdre exactement ce
     * que `level_reason` sert à rendre exploitable.
     */
    private fun reportResult(result: JSONObject) {
        report("niveau         ${result.getString("level")}")
        report("motif          ${result.getString("level_reason")}")
        report("profil juge    ${result.getString("profile")}")
        val properties = result.getJSONObject("properties")
        for (name in properties.keys()) {
            val property = properties.getJSONObject(name)
            report("  %-12s %s   %s".format(name, property.getString("grade"), property.optString("evidence")))
        }
        val flags = result.getJSONArray("flags")
        report("drapeaux       ${if (flags.length() == 0) "aucun" else flags.join(", ")}")
        report("politique      ${result.get("policy")}")
    }

    private fun ms(startNanos: Long): Double = (System.nanoTime() - startNanos) / 1_000_000.0

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
}
