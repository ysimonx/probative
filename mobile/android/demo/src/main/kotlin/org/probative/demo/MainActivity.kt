package org.probative.demo

import android.graphics.BitmapFactory
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.util.TypedValue
import android.view.View
import android.view.WindowInsets
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.camera.view.PreviewView
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread
import org.json.JSONObject
import org.probative.core.capture.CapturedImage
import org.probative.core.capture.CaptureSession
import org.probative.core.envelope.Sealer
import org.probative.core.freshness.PlayIntegrity
import org.probative.core.freshness.PlayIntegrityFreshness
import org.probative.core.keys.KeystoreKeys
import org.probative.core.payload.CapturePayload
import org.probative.core.payload.CorePayload
import org.probative.core.sensors.Sensors

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
public class MainActivity : ComponentActivity() {

    /**
     * Les deux sondes, et ce qui les sépare.
     *
     * [SEAL] scelle des octets remis : aucun capteur, profil `core`. [CAPTURE]
     * acquiert une photo par le cœur : position et corroboration exigées,
     * profil `capture`, et `origin` plafonné à B par la recapture analogique.
     *
     * Chacune son étiquette de journal, parce que les commandes documentées
     * filtrent dessus et qu'un tampon mêlant les deux se lit mal.
     */
    private enum class Probe(val tag: String, val titre: String) {
        CAPTURE("PROBATIVE_A42", "sonde A4.2 : acquisition photo, profil capture"),
        SEAL("PROBATIVE_A41", "sonde A4.1 : enveloppe complete, profil core"),
    }

    private companion object {
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

        /** Un seul code : toutes les autorisations partent d'un même appel. */
        const val REQUEST_PERMISSIONS = 1
    }

    private lateinit var view: TextView
    private lateinit var permissions: Permissions
    private lateinit var permissionsView: TextView
    private lateinit var action: Button
    private lateinit var header: TextView
    private val lines = StringBuilder()

    /** La sonde en cours. Fixée au lancement, puis par les boutons. */
    private var probe = Probe.CAPTURE

    /**
     * Le viseur, et la session qui l'alimente.
     *
     * La session est **gardée ouverte** entre deux prises : c'est tout l'objet
     * de l'aperçu. Une session par photo repaierait à chaque fois la mise sous
     * tension du capteur et le délai de garde — les termes que la
     * décomposition montre comme structurels.
     */
    private lateinit var viseur: PreviewView
    private var session: CaptureSession? = null

    /** Le tableau des prises, reconstruit après chaque campagne. */
    private lateinit var tableau: LinearLayout
    private lateinit var racine: LinearLayout

    /**
     * Ce qu'un scellement rend à l'appelant — au-delà de l'enveloppe.
     *
     * [image] est nulle hors acquisition : c'est ce qui distingue les deux
     * profils, et la garder nullable évite d'inventer des dimensions pour des
     * octets remis qui n'en ont pas.
     */
    private class Scelle(
        val sealed: org.probative.core.envelope.SealedEnvelope,
        val octets: ByteArray,
        val image: CapturedImage?,
        val decomposition: String?,
    )

    /** La sonde ne part qu'une fois, quel que soit le chemin qui y mène. */
    private var started = false

    /** Une campagne occupe la caméra : une seule à la fois. */
    @Volatile private var enCours = false

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
        header = TextView(this).apply {
            setPadding(48, 96, 48, 24)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            text = identity()
        }
        view = TextView(this).apply {
            setTextIsSelectable(true)
            setPadding(48, 0, 48, 48)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        // Le préambule d'autorisations est **épinglé**, comme l'identité du
        // binaire et pour la même raison : c'est une condition de la campagne,
        // pas un événement du journal. Poussé hors champ par le verdict, il
        // laisserait lire un résultat sans savoir sous quelles autorisations
        // il a été obtenu.
        permissions = Permissions(this)
        permissionsView = TextView(this).apply {
            setPadding(48, 0, 48, 8)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        action = Button(this).apply { setOnClickListener { onAction() } }

        // Deux boutons plutôt qu'un sélecteur : la démonstration reste sans
        // ressources, et relancer est le geste le plus fréquent d'une campagne.
        val boutons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(
                Button(this@MainActivity).apply {
                    text = "A4.2 photo"
                    setOnClickListener { relancer(Probe.CAPTURE) }
                },
            )
            addView(
                Button(this@MainActivity).apply {
                    text = "A4.1 octets"
                    setOnClickListener { relancer(Probe.SEAL) }
                },
            )
        }

        viseur = PreviewView(this)
        // Le tableau des prises vit sous le journal, et chaque ligne se touche.
        tableau = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 8, 48, 8)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(header, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(permissionsView, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(action, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
            addView(boutons, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
            // Le viseur occupe une bande fixe : le journal reste lisible en
            // dessous, et c'est lui qu'on relit pendant une campagne.
            addView(viseur, LinearLayout.LayoutParams(MATCH_PARENT, 700))
            // Le déclencheur va **sous** le viseur, et il est le seul bouton
            // large de l'écran. Les deux boutons de sonde, au-dessus et nommés
            // d'après des étapes du plan, ne se lisaient pas comme un
            // déclencheur — personne ne cherche « A4.2 photo » pour prendre
            // une photo.
            addView(
                Button(this@MainActivity).apply {
                    text = "DECLENCHER"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
                    setOnClickListener { relancer(Probe.CAPTURE) }
                },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
            addView(
                ScrollView(this@MainActivity).apply { addView(view) },
                LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f),
            )
            addView(tableau, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        }
        racine = root

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

        refreshPermissions()
        rafraichirTableau()
        if (permissions.needsRequest()) {
            // La sonde **attend**. A4.1 n'a besoin d'aucune de ces
            // autorisations — elle scelle des octets remis — mais une boîte de
            // dialogue affichée pendant la mesure fausse les latences, et
            // `media[6]` comme `prepare` sont précisément ce qu'on mesure. La
            // leçon de C4.2 vaut donc aussi pour le profil `core`.
            permissions.request(REQUEST_PERMISSIONS)
        } else {
            startProbe()
        }
    }

    /** Retour des Réglages : l'état a pu changer sans passer par la demande. */
    override fun onResume() {
        super.onResume()
        refreshPermissions()
    }

    // `ComponentActivity` déclare ce rappel avec `Array<String>`, non
    // `Array<out String>` comme `Activity` : la signature n'est pas au choix.
    @Deprecated("remplacé par ActivityResultContracts, hors de portée de cette démonstration")
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissionNames: Array<String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissionNames, grantResults)
        if (requestCode != REQUEST_PERMISSIONS) return
        refreshPermissions()
        // Accordées ou refusées, la sonde part : A4.1 n'en dépend pas, et
        // s'arrêter sur un refus priverait d'un résultat que le refus ne
        // dégrade même pas.
        startProbe()
    }

    /**
     * Le préambule tel qu'il s'affiche — une ligne par autorisation.
     *
     * Le bouton porte l'action possible et *seulement* elle : demander tant
     * qu'une autorisation n'a jamais été soumise, conduire aux Réglages
     * lorsqu'un refus est définitif, disparaître quand il n'y a plus rien à
     * faire. Un bouton qui n'afficherait plus aucune boîte de dialogue est
     * pire que pas de bouton du tout.
     */
    private fun refreshPermissions() {
        permissionsView.text = permissions.entries().joinToString("\n") {
            "%s %-10s %-22s %s".format(it.state.symbol, it.label, it.state.label, it.note)
        }
        when {
            permissions.needsRequest() -> {
                action.text = "Tout autoriser"
                action.visibility = View.VISIBLE
            }
            permissions.blocked() -> {
                action.text = "Ouvrir les reglages"
                action.visibility = View.VISIBLE
            }
            else -> action.visibility = View.GONE
        }
    }

    private fun onAction() {
        if (permissions.needsRequest()) {
            permissions.request(REQUEST_PERMISSIONS)
        } else {
            permissions.openSettings()
        }
    }

    /**
     * Choisit la sonde de lancement selon ce qui peut réellement aboutir.
     *
     * A4.2 sans caméra ni position produirait un échec qui n'apprend rien —
     * c'est la case du plan de spike que le mécanisme existait sans que rien ne
     * l'appelle. On retombe sur A4.1, qui ne dépend d'aucune autorisation, et
     * on le dit plutôt que de le subir.
     */
    private fun relancer(choix: Probe) {
        // **Refuser plutôt que d'empiler.** Deux campagnes concurrentes
        // partagent la caméra, et `CaptureSession.open` commence par
        // `unbindAll` : la seconde tue la session de la première, qui échoue
        // sur « Camera is closed ». Trouvé en campagne le 2026-08-17, sur deux
        // appuis rapprochés — et le symptôme n'accusait pas la cause.
        if (enCours) {
            report("campagne deja en cours : appui ignore")
            return
        }
        probe = choix
        started = false
        lines.setLength(0)
        header.text = identity()
        view.text = ""
        startProbe()
    }

    /** Play Integrity, Keystore et le réseau bloquent : jamais sur le fil principal. */
    private fun startProbe() {
        if (started) return
        if (probe == Probe.CAPTURE && !permissions.readyForCapture()) {
            probe = Probe.SEAL
            header.text = identity()
            report("A4.2 impossible : camera ou position manquante, repli sur A4.1")
        }
        started = true
        enCours = true
        thread {
            try {
                executer()
            } finally {
                enCours = false
            }
        }
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
        appendLine("probative — ${probe.titre}")
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
        Log.i(probe.tag, text)
        lines.appendLine(text)
        Handler(Looper.getMainLooper()).post { view.text = lines }
    }

    private fun executer() {
        // L'identité du binaire est à l'écran en permanence (`identity`) ; ici
        // on ne la journalise qu'une fois, parce que logcat n'a pas d'en-tête
        // épinglé et qu'un extrait de journal sans version ne vaut rien.
        Log.i(probe.tag, identity())

        // Relu ici, jamais hérité du préambule : l'état a pu changer entre
        // l'affichage et le lancement — un retour des Réglages, une réponse
        // arrivée entre-temps. Et il est **imprimé**, pas seulement affiché :
        // un extrait de logcat rapatrié sans l'écran doit permettre de
        // distinguer un capteur muet d'une autorisation manquante.
        report("autorisations  ${permissions.summary()}")

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
        val attendu =
            if (probe == Probe.CAPTURE) CapturePayload.PROFILE else CorePayload.PROFILE
        val issued = server.nonce(KeystoreKeys.kid(alias), attendu)
        val nonce = Base64.decode(issued.getString("nonce_b64"), Base64.NO_WRAP)
        val profile = issued.getString("profile")
        report("")
        report("nonce          ${nonce.size} octets, profil $profile, ttl ${issued.getInt("ttl_ms")} ms")
        // Le profil signé doit être celui du nonce : le serveur rejette une
        // enveloppe dont le profil diffère, et il a raison de le faire — sans
        // ce contrôle un client compromis déclarerait `core` pour une
        // acquisition et échapperait au plafond de recapture.
        check(profile == attendu) {
            "le serveur a emis un nonce pour le profil $profile, ce sceau produit $attendu"
        }

        // ── 4. Scellement ─────────────────────────────────────────────────
        val sealer = Sealer(
            context = this,
            deployment = DEPLOYMENT,
            keyAlias = alias,
            appVersion = BuildConfig.VERSION_NAME,
            freshness = PlayIntegrityFreshness(provider),
        )
        val scelle =
            if (probe == Probe.CAPTURE) scellerPhoto(sealer, nonce) else scellerOctets(sealer, nonce)
        val sealed = scelle.sealed
        val octets = scelle.octets

        report("defi R1        ${b64(sealed.challenge)}")
        report("enveloppe      ${sealed.bytes.size} octets")

        // ── 5. Verdict ────────────────────────────────────────────────────
        start = System.nanoTime()
        val result = server.verify(sealed.bytes, octets)
        report("verification   %.0f ms".format(ms(start)))
        report("")
        reportResult(result)
        consigner(result, scelle, enrolled.getString("kid_hex"))
    }

    /**
     * Ajoute la prise au tableau et le réaffiche.
     *
     * On conserve **les octets**, pas seulement leurs empreintes : sans eux le
     * verdict sur le contenu ne vaut rien, et aucune recompression ne les
     * rattrape (ADR-0007 point 5).
     */
    private fun consigner(result: JSONObject, scelle: Scelle, kid: String) {
        val proprietes = result.getJSONObject("properties")
        val prise = Historique.ajouter(
            profil = result.getString("profile"),
            niveau = result.getString("level"),
            motif = result.getString("level_reason"),
            proprietes = proprietes.keys().asSequence().map {
                "%-10s %s".format(it, proprietes.getJSONObject(it).getString("grade"))
            }.toList(),
            drapeaux = result.getJSONArray("flags").let {
                if (it.length() == 0) "aucun" else it.join(", ")
            },
            mediaSixMs = scelle.sealed.signLatencyMs,
            photo = scelle.image?.bytes,
            largeur = scelle.image?.pixelWidth ?: 0,
            hauteur = scelle.image?.pixelHeight ?: 0,
            typeMime = scelle.image?.format?.mimeType ?: CONTENT_TYPE,
            enveloppe = scelle.sealed.bytes,
            defiR1 = b64(scelle.sealed.challenge),
            kid = kid,
            decomposition = scelle.decomposition,
        )
        report("")
        report("prise n°${prise.index} consignee — ${Historique.compte()} au tableau")
        report(Historique.dispersion(prise.profil))
        Handler(Looper.getMainLooper()).post { rafraichirTableau() }
    }

    /**
     * Scellement d'octets remis — profil `core`. Aucun capteur.
     *
     * Deux chiffres, et **ils ne mesurent pas la même chose**. Le premier est
     * du temps mural, chronométré par la sonde autour de l'appel : il englobe
     * le jeton de fraîcheur et la signature. Le second est celui que le cœur a
     * scellé, et le seul que `max_sign_latency_ms` confronte. Les afficher côte
     * à côte sans le dire a déjà fait conclure à une marge étroite là où elle
     * n'était pas mesurée — l'erreur corrigée côté iOS le 2026-08-15.
     */
    private fun scellerOctets(sealer: Sealer, nonce: ByteArray): Scelle {
        val start = System.nanoTime()
        val sealed = sealer.seal(CONTENT, CONTENT_TYPE, nonce)
        report("")
        report("scellement     %.0f ms de temps mural".format(ms(start)))
        report("charge utile   ${sealed.payloadBytes.size} octets")
        report(
            "media[6]       ${sealed.signLatencyMs} ms depuis la remise des octets" +
                " — seul chiffre confronte au seuil",
        )
        return Scelle(sealed, CONTENT, null, null)
    }

    /**
     * Acquisition et scellement — profil `capture`.
     *
     * **L'ordre des trois premières lignes est le fond de cette sonde.** La
     * collecte démarre *avant* l'acquisition et n'est moissonnée qu'après :
     * la jointure se situe en aval de l'obturateur, donc un capteur qui survit
     * à la capture verse son excédent dans `media[6]`. Lancer la corroboration
     * après la photo a coûté +4,2 s dans ce champ côté iOS, faisant accuser
     * une latence anormale là où il n'y en avait aucune.
     */
    private fun scellerPhoto(sealer: Sealer, nonce: ByteArray): Scelle {
        val start = System.nanoTime()
        val capteurs = Sensors.begin(this)
        try {
            val image = sessionOuverte().capture()
            val t = image.timings
            report("")
            report(
                "capture        %d ms — %d octets, %dx%d, %s".format(
                    t.photoMs, image.bytes.size, image.pixelWidth, image.pixelHeight,
                    image.format.mimeType,
                ),
            )
            // La décomposition sépare ce qui est structurel (mise sous tension,
            // et qui disparaîtrait avec un aperçu), ce qui est en dur (garde),
            // ce qui dépend de la scène (3A), et le seul terme qui pèse dans
            // `media[6]` (encodage). Une somme ne se pilote pas.
            // `capture` ne compte que la photo ; l'ouverture de session et le
            // cadrage sont rapportés à part. Les additionner ferait mesurer une
            // séance là où on veut mesurer une prise de vue.
            report(
                "               ouverture: config %d + session %d + garde %d ms%s".format(
                    t.configureMs, t.startupMs, t.settleMs,
                    if (t.idleMs > 0) " — puis %d ms de cadrage".format(t.idleMs) else "",
                ),
            )
            report(
                "               photo: 3A %d │obturateur│ encodage %d ms".format(
                    t.shutterLagMs, t.encodeMs,
                ),
            )

            val claims = capteurs.claims()
            report(
                "corroboration  %d ms cumule — %s".format(
                    ms(start).toLong(),
                    if (claims.isEmpty()) "aucune" else claims.joinToString(", ") { it.type },
                ),
            )

            val position = capteurs.position(image.shutterElapsedMs)
            checkNotNull(position) {
                "aucun point de position exploitable : le profil capture l'exige"
            }
            report(
                "position       %s, %.0f m, age %d ms%s".format(
                    position.provider.label, position.horizontalAccuracy, position.fixAgeMs,
                    position.satellites?.let { ", $it satellites" } ?: "",
                ),
            )

            val sealStart = System.nanoTime()
            val sealed = sealer.seal(image, position, claims, nonce)
            report("scellement     %.0f ms de temps mural".format(ms(sealStart)))
            report("charge utile   ${sealed.payloadBytes.size} octets")
            report(
                "media[6]       ${sealed.signLatencyMs} ms depuis l'obturateur" +
                    " — seul chiffre confronte au seuil",
            )
            return Scelle(
                sealed,
                image.bytes,
                image,
                "config %d + session %d + garde %d ms, cadrage %d ms, 3A %d │obturateur│ encodage %d ms".format(
                    t.configureMs, t.startupMs, t.settleMs, t.idleMs, t.shutterLagMs, t.encodeMs,
                ),
            )
        } finally {
            capteurs.stop()
        }
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

    /**
     * La session, ouverte à la demande puis **gardée**.
     *
     * C'est ce qui distingue un viseur d'une prise isolée. La première photo
     * paie encore la mise sous tension et le délai de garde ; les suivantes
     * non, et `idle` dira combien de temps la session a attendu — c'est-à-dire
     * combien de temps l'utilisateur a eu pour cadrer.
     *
     * `attachPreview` ne donne au cœur qu'une surface. L'application garde la
     * vue, sa taille et sa place : le cœur possède la caméra, pas l'écran
     * (ADR-0008).
     */
    private fun sessionOuverte(): CaptureSession {
        session?.let { return it }
        val ouverte = CaptureSession.open(this, this)
        // `PreviewView.surfaceProvider` se lit sur le fil principal, et cette
        // méthode tourne en arrière-plan — la sonde n'a pas le droit de bloquer
        // l'interface. On fait donc l'aller-retour explicitement plutôt que de
        // s'en remettre au hasard d'un accès concurrent qui « marche souvent ».
        val pose = CountDownLatch(1)
        runOnUiThread {
            ouverte.attachPreview(viseur.surfaceProvider)
            pose.countDown()
        }
        pose.await()
        session = ouverte
        report("viseur         session ouverte et apercu rattache")
        return ouverte
    }

    override fun onDestroy() {
        super.onDestroy()
        // Une session qui survit à l'écran garde la caméra et vide la
        // batterie ; elle ne se referme pas toute seule.
        session?.close()
        session = null
    }

    /**
     * Le tableau, reconstruit en entier plutôt que mis à jour ligne à ligne.
     *
     * Quelques dizaines de prises au plus : la simplicité vaut mieux ici qu'un
     * adaptateur, et la démonstration doit rester assez pauvre pour qu'on ne
     * soit jamais tenté d'y loger de la logique.
     */
    private fun rafraichirTableau() {
        tableau.removeAllViews()
        val prises = Historique.toutes()
        tableau.addView(
            TextView(this).apply {
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                text = if (prises.isEmpty()) {
                    "aucune prise"
                } else {
                    "${prises.size} prise(s) — toucher une ligne pour la consulter"
                }
            },
        )
        for (prise in prises.asReversed()) {
            tableau.addView(
                TextView(this).apply {
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                    setPadding(0, 12, 0, 12)
                    text = prise.ligne()
                    isClickable = true
                    setOnClickListener { montrerFiche(prise) }
                },
            )
        }
    }

    /**
     * La fiche d'une prise : la photo, le verdict, et les octets.
     *
     * La vignette est décodée **sous-échantillonnée** — un JPEG de 3264×2448
     * occuperait une trentaine de mégaoctets une fois décodé. Les octets
     * conservés, eux, restent intacts : on ne montre jamais autre chose que ce
     * qui a été scellé, mais on ne le montre pas en pleine résolution.
     */
    private fun montrerFiche(prise: Prise) {
        val contenu = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
        }
        contenu.addView(
            Button(this).apply {
                text = "← retour au tableau"
                setOnClickListener { setContentView(racine) }
            },
        )
        prise.photo?.let { octets ->
            val options = BitmapFactory.Options().apply { inSampleSize = 8 }
            BitmapFactory.decodeByteArray(octets, 0, octets.size, options)?.let { vignette ->
                contenu.addView(
                    ImageView(this).apply { setImageBitmap(vignette) },
                    LinearLayout.LayoutParams(MATCH_PARENT, 900),
                )
            }
        }
        contenu.addView(
            TextView(this).apply {
                setTextIsSelectable(true)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                text = fiche(prise)
            },
        )
        setContentView(ScrollView(this).apply { addView(contenu) })
    }

    private fun fiche(prise: Prise): String = buildString {
        appendLine("prise n°${prise.index} — ${prise.heure}")
        appendLine()
        appendLine("niveau         ${prise.niveau}")
        appendLine("motif          ${prise.motif}")
        appendLine("profil         ${prise.profil}")
        for (p in prise.proprietes) appendLine("  $p")
        appendLine("drapeaux       ${prise.drapeaux}")
        appendLine()
        appendLine("media[6]       ${prise.mediaSixMs} ms — seul chiffre confronte au seuil")
        prise.decomposition?.let { appendLine("acquisition    $it") }
        appendLine()
        if (prise.photo != null) {
            appendLine("media          ${prise.largeur}×${prise.hauteur}, ${prise.typeMime}")
            appendLine("               ${prise.photo.size} octets, tels que scelles")
        } else {
            appendLine("media          octets remis, ${prise.typeMime}")
        }
        appendLine("enveloppe      ${prise.enveloppe.size} octets")
        appendLine("kid            ${prise.kid}")
        appendLine("defi R1        ${prise.defiR1}")
        appendLine()
        appendLine("enveloppe (base64, selectionnable) :")
        appendLine(b64(prise.enveloppe))
    }

    private fun ms(startNanos: Long): Double = (System.nanoTime() - startNanos) / 1_000_000.0

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
}
