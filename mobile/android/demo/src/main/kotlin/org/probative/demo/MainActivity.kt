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
import org.probative.core.freshness.KeyAttestationFreshness
import org.probative.core.freshness.PlayIntegrity
import org.probative.core.freshness.PlayIntegrityFreshness
import org.probative.core.keys.KeystoreKeys
import org.probative.core.payload.CapturePayload
import org.probative.core.payload.CorePayload
import org.probative.core.sensors.SensorRun
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

        /**
         * Bornes d'une série, au premier des deux atteint.
         *
         * Assez lâches pour ne pas rappeler le quota Play Integrity, assez
         * serrées pour que la fenêtre pendant laquelle l'appareil a pu être
         * compromis reste courte. Ce sont des points de départ, à recalibrer
         * comme les seuils du vérificateur : ils n'ont rien d'une vérité.
         */
        const val MAX_PRISES_PAR_SERIE = 5
        const val DUREE_MAX_SERIE_MS = 120_000L
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
    private lateinit var statut: TextView
    private lateinit var ecranTableau: LinearLayout
    private lateinit var ecranResultat: LinearLayout

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

    /** Une campagne occupe la caméra : une seule à la fois. */
    @Volatile private var enCours = false

    /**
     * L'appareil, enrôlé **une fois par lancement** et non par capture.
     *
     * Ce n'était pas qu'un gaspillage : une clé neuve à chaque campagne donne
     * un `kid` neuf, donc un appareil neuf pour le serveur, donc jamais de
     * maillon précédent. **Le chaînage était impossible par construction**, et
     * le drapeau `CHAIN_FIRST_LINK_UNKNOWN` en était le symptôme.
     *
     * `prepare` est ici pour la même raison, plus une seconde : Google applique
     * à la mise en route du fournisseur un quota plus strict qu'aux demandes de
     * jeton. La répéter à chaque prise est une piste sérieuse pour le bridage
     * observé le 2026-08-17.
     */
    private var alias: String? = null
    private var provider: PlayIntegrity.Provider? = null

    /** Empreinte de l'enveloppe précédente — le maillon à chaîner. */
    private var dernierDigest: ByteArray? = null

    /** Série courante. Clore incrémente : la suivante repart d'une tête. */
    private var serie = 1

    /**
     * Mode hors ligne — la fraîcheur vient de la puce, pas de Google.
     *
     * Sert à **mesurer** ce que coûte l'attestation de clé par capture : temps
     * mural du scellement et taille d'enveloppe. Le serveur rejettera ces
     * enveloppes, le type `key-attestation` lui étant inconnu — c'est attendu,
     * et l'échec doit se lire dans le journal plutôt que d'être masqué.
     */
    private var horsLigne = false
    private lateinit var boutonHorsLigne: Button

    /**
     * Les capteurs, démarrés **avec le viseur** et non à chaque capture.
     *
     * Lancés au déclenchement, ils n'ont pas le temps d'acquérir un point : la
     * moisson attend alors, et cette attente tombe en aval de l'obturateur donc
     * dans `media[6]`. Mesuré le 2026-08-17 : 6,3 s d'attente, `media[6]` à
     * 6 485 ms, **au-dessus du seuil de 3 000**, sur une capture parfaitement
     * honnête.
     *
     * Troisième occurrence du même défaut, après l'enrôlement et la session de
     * capture : **ce qui est coûteux et réutilisable n'a rien à faire dans le
     * chemin par capture.**
     */
    private var capteurs: SensorRun? = null

    /**
     * Le déclencheur, barré tant qu'aucun point n'est arrivé.
     *
     * **On barre sur la présence, jamais sur la qualité.** Un point à 500 m
     * passe et le serveur le note en C : c'est son travail, pas celui du
     * client (invariant 1). Mais sans aucun point, le profil `capture` ne peut
     * pas être produit — un bouton grisé qui dit pourquoi vaut mieux qu'une
     * acquisition qui échoue après l'obturateur.
     *
     * Ce qu'il supprime au passage : le dernier endroit où l'attente d'un
     * capteur entrait dans `media[6]`. `position()` bloquait jusqu'à 8 s en
     * aval de l'obturateur quand aucun point n'était encore là.
     */
    private lateinit var boutonDeclencher: Button
    private val rafraichisseur = Handler(Looper.getMainLooper())
    private var prisesDansSerie = 0
    private var debutSerieMs = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        permissions = Permissions(this)
        construireEcrans()

        montrerTableau()
        if (permissions.needsRequest()) {
            // Demandées avant toute mesure, jamais pendant : une boîte de
            // dialogue affichée au milieu d'une acquisition fausse les latences,
            // et ce sont elles qu'on mesure. Leçon de C4.2.
            permissions.request(REQUEST_PERMISSIONS)
        }
    }

    /**
     * Trois écrans, et un seul chemin entre eux.
     *
     * Le tableau est la page d'accueil et il peut être vide — c'est même son
     * état initial. « + » conduit au viseur, le déclencheur lance la campagne,
     * le résultat s'affiche, et le refermer ramène au tableau **augmenté d'une
     * ligne**. Chaque écran ne montre qu'une chose : l'empilement précédent
     * mêlait préambule, viseur, journal et tableau sur une seule page, où le
     * déclencheur se perdait au milieu.
     */
    private fun construireEcrans() {
        header = TextView(this).apply {
            setPadding(48, 96, 48, 16)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            text = identity()
        }
        permissionsView = TextView(this).apply {
            setPadding(48, 0, 48, 8)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        action = Button(this).apply { setOnClickListener { onAction() } }
        tableau = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 8, 48, 8)
        }
        viseur = PreviewView(this)
        statut = TextView(this).apply {
            setPadding(48, 4, 48, 4)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            text = "pret"
        }
        view = TextView(this).apply {
            setTextIsSelectable(true)
            setPadding(48, 0, 48, 48)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }

        // ── Écran 1 : le viseur et le tableau ────────────────────────────
        //
        // Le flux reste visible **pendant** qu'on consulte le tableau, et « + »
        // est le déclencheur. Un écran viseur séparé obligerait à promener la
        // `PreviewView` d'un parent à l'autre, ce qui détruit et recrée la
        // surface à chaque aller-retour — coût inutile, et une occasion de
        // perdre l'aperçu au mauvais moment.
        ecranTableau = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(header, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(permissionsView, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(action, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
            addView(viseur, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1.4f))
            boutonDeclencher = Button(this@MainActivity).apply {
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
                setOnClickListener { lancer(Probe.CAPTURE) }
            }
            addView(boutonDeclencher, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(statut, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(
                ScrollView(this@MainActivity).apply { addView(tableau) },
                LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f),
            )
            addView(
                Button(this@MainActivity).apply {
                    text = "journal de la derniere campagne"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                    setOnClickListener { afficher(ecranResultat) }
                },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
            // La sonde sans caméra reste accessible, discrètement : elle sert à
            // isoler ce qui ne dépend pas de l'acquisition.
            addView(
                Button(this@MainActivity).apply {
                    text = "j'ai fini mes prises de vues (facultatif)"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
                    setOnClickListener { clore() }
                },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
            boutonHorsLigne = Button(this@MainActivity).apply {
                text = libelleHorsLigne()
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setOnClickListener {
                    horsLigne = !horsLigne
                    text = libelleHorsLigne()
                }
            }
            addView(
                boutonHorsLigne,
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
            addView(
                Button(this@MainActivity).apply {
                    text = "sceller des octets remis (profil core)"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                    setOnClickListener { lancer(Probe.SEAL) }
                },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
        }

        // ── Écran 3 : le résultat ─────────────────────────────────────────
        ecranResultat = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(
                Button(this@MainActivity).apply {
                    text = "fermer  →  retour au tableau"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
                    setOnClickListener { montrerTableau() }
                },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
            addView(
                ScrollView(this@MainActivity).apply { addView(view) },
                LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f),
            )
        }
    }

    /**
     * Affiche un écran en lui rendant les marges système.
     *
     * Depuis `targetSdk 35` l'affichage bord à bord est imposé : sans ce recul,
     * les premières lignes passent sous la barre d'état, ce qui ressemble à s'y
     * méprendre à un défilement.
     */
    private fun afficher(ecran: View) {
        ecran.setOnApplyWindowInsetsListener { v, insets ->
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
        setContentView(ecran)
        ecran.requestApplyInsets()
    }

    private fun montrerTableau() {
        refreshPermissions()
        rafraichirTableau()
        afficher(ecranTableau)
        ouvrirViseurSiPossible()
        rafraichirDeclencheur()
        rafraichisseur.removeCallbacksAndMessages(null)
        rafraichisseur.post(object : Runnable {
            override fun run() {
                rafraichirDeclencheur()
                rafraichisseur.postDelayed(this, 1_000)
            }
        })
    }

    /**
     * Allume l'aperçu dès que le tableau s'affiche.
     *
     * La session s'ouvre **avant** qu'on appuie, et c'est tout l'objet d'un
     * aperçu : le capteur est déjà sous tension et convergé au déclenchement.
     * `CaptureTimings.idleMs` mesurera ce temps de cadrage, et
     * `shutterLagMs` dira ce que la convergence coûte encore.
     */
    private fun ouvrirViseurSiPossible() {
        if (session != null || enCours || !permissions.readyForCapture()) return
        thread {
            try {
                if (capteurs == null) {
                    capteurs = Sensors.begin(this)
                    report("capteurs       demarres avec le viseur — un point sera pret au declenchement")
                }
                sessionOuverte()
            } catch (e: Exception) {
                report("ECHEC ouverture du viseur : ${e.message}")
            }
        }
    }

    /**
     * Lance une campagne **sans quitter le tableau**.
     *
     * Basculer d'écran retirait la `PreviewView` de la fenêtre, donc détruisait
     * la surface d'aperçu *pendant* la capture. Outre l'aperçu qui s'éteignait
     * sous les yeux, cela fausse la mesure : la campagne du 2026-08-17 qui
     * attribuait à l'aperçu une convergence 3A de 5 à 6 secondes se faisait
     * précisément pendant cette destruction de surface. On ne bouge donc plus
     * rien tant que la caméra travaille.
     *
     * Le résultat s'annonce sur une ligne d'état ; le détail se consulte en
     * touchant la ligne du tableau, quand on le veut.
     */
    private fun lancer(choix: Probe) {
        if (enCours) {
            report("campagne deja en cours : appui ignore")
            return
        }
        if (choix == Probe.CAPTURE && !permissions.readyForCapture()) {
            statut.text = "camera ou position manquante : acquisition impossible"
            return
        }
        if (choix == Probe.CAPTURE && capteurs?.aUnPoint != true) {
            statut.text = "aucun point de position : le profil capture l'exige"
            return
        }
        probe = choix
        header.text = identity()
        lines.setLength(0)
        view.text = ""
        statut.text = "campagne en cours…"
        enCours = true
        thread {
            try {
                executer()
            } finally {
                enCours = false
                Handler(Looper.getMainLooper()).post {
                    clotureAutomatique()
                    statut.text = resume()
                    rafraichirTableau()
                }
            }
        }
    }

    /**
     * Clôt la série : la prochaine prise repartira d'une tête.
     *
     * Le geste est nécessaire, et pas seulement confortable. ADR-0009 fait
     * d'une série un objet borné aux deux bouts ; une série qu'on abandonne
     * reste **ouverte par le bas**, et rien ne dit alors jusqu'où l'appareil
     * est resté sain. Une application réelle devra donc offrir ce geste, pas
     * seulement un bouton « photo suivante ».
     */
    /**
     * Clôt la série d'elle-même — au bout de [MAX_PRISES_PAR_SERIE] prises ou
     * de [DUREE_MAX_SERIE_MS], au premier des deux.
     *
     * **Ce que cela apporte aujourd'hui, et ce que non.** Tant que `freshness`
     * est obligatoire au format, *toutes* les enveloppes portent un jeton :
     * la série est donc attestée en chacun de ses points, et la segmenter ne
     * change rien à ce qui est prouvé. Ce mécanisme est la **politique**, pas
     * encore son effet — il décidera où se placent les points attestés le jour
     * où les maillons cesseront d'en porter (ADR-0009 point 2). Le dire
     * maintenant évite de croire la fenêtre bornée par une borne qui n'agit
     * pas encore.
     *
     * Ce qu'il apporte déjà : l'utilisateur n'a plus rien à presser, et le
     * tableau montre des séries plutôt qu'une liste plate.
     */
    private fun clotureAutomatique() {
        val trop = prisesDansSerie >= MAX_PRISES_PAR_SERIE
        val vieille = debutSerieMs != 0L &&
            System.currentTimeMillis() - debutSerieMs >= DUREE_MAX_SERIE_MS
        if (!trop && !vieille) return
        val motif = if (trop) "$MAX_PRISES_PAR_SERIE prises" else "${DUREE_MAX_SERIE_MS / 1000} s"
        report("serie $serie close automatiquement ($motif)")
        reinitialiserSerie()
    }

    private fun reinitialiserSerie() {
        dernierDigest = null
        prisesDansSerie = 0
        debutSerieMs = 0L
        serie += 1
    }

    /**
     * Passage en arrière-plan : la série se clôt.
     *
     * C'est le geste implicite « j'ai fini », et il rattrape le cas que la
     * minuterie manque — l'utilisateur qui pose l'appareil ou quitte
     * l'application juste après sa dernière photo, sans qu'aucun tic ne vienne
     * jamais.
     */
    override fun onStop() {
        super.onStop()
        if (dernierDigest != null) {
            report("serie $serie close : passage en arriere-plan")
            reinitialiserSerie()
        }
    }

    private fun clore() {
        if (enCours) {
            statut.text = "campagne en cours : clôture refusée"
            return
        }
        if (dernierDigest == null) {
            statut.text = "aucune série ouverte"
            return
        }
        reinitialiserSerie()
        statut.text = "série close — la prochaine prise ouvrira la série $serie"
    }

    /** Ce que la dernière campagne a donné, en une ligne. */
    private fun resume(): String {
        val derniere = Historique.toutes().lastOrNull() ?: return "aucune prise — voir le journal"
        return "prise n°%d : %s — %s, media[6] %d ms".format(
            derniere.index, derniere.profil, derniere.niveau, derniere.mediaSixMs,
        )
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
        // Rien ne part tout seul : c'est « + » qui déclenche. On se contente
        // d'allumer l'aperçu si les autorisations viennent d'arriver.
        rafraichirTableau()
        ouvrirViseurSiPossible()
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

    /**
     * Remet le déclencheur à l'état de ce qu'on sait faire.
     *
     * Rafraîchi à la seconde tant que l'écran vit : le point arrive de façon
     * asynchrone, et rien d'autre ne préviendrait.
     */
    private fun rafraichirDeclencheur() {
        val pret = permissions.readyForCapture()
        val point = capteurs?.aUnPoint == true
        boutonDeclencher.isEnabled = pret && point && !enCours
        boutonDeclencher.text = when {
            !pret -> "camera ou position non autorisee"
            !point -> "en attente d'un point de position…"
            else -> "+   prendre une photo"
        }
    }

    private fun libelleHorsLigne(): String =
        if (horsLigne) "fraicheur : attestation de cle (hors ligne)" else "fraicheur : Play Integrity"

    private fun onAction() {
        if (permissions.needsRequest()) {
            permissions.request(REQUEST_PERMISSIONS)
        } else {
            permissions.openSettings()
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
        report("fraicheur      ${if (horsLigne) "key-attestation — hors ligne" else "play-integrity"}")

        val cloudProjectNumber = BuildConfig.CLOUD_PROJECT_NUMBER
        if (cloudProjectNumber <= 0L) {
            // Sans jeton, l'enveloppe n'aurait pas de preuve de fraîcheur :
            // il n'y a pas de version dégradée de cette sonde.
            report("ARRET — numero de projet Google Cloud absent.")
            report("  reconstruire avec -Pprobative.cloudProjectNumber=<numero>")
            return
        }

        try {
            sequence(cloudProjectNumber)
        } catch (e: DevServer.Refused) {
            report("ECHEC serveur  HTTP ${e.status}")
            report("  ${e.detail}")
        } catch (e: Exception) {
            report("ECHEC          ${e.javaClass.simpleName}")
            report("  ${e.cause?.message ?: e.message}")
        }
        // La clé n'est plus détruite ici : elle vit le temps du lancement,
        // comme en production elle vit le temps de l'installation. C'est ce
        // qui donne un `kid` stable, donc un chaînage possible.
    }

    /** Les cinq temps de la boucle, dans l'ordre où le format les impose. */
    /**
     * Met en route le fournisseur et enrôle l'appareil — **une seule fois**.
     *
     * En production, l'enrôlement est un événement d'installation, pas de
     * capture : la clé matérielle vit dans le Keystore et le serveur la connaît
     * par son `kid`. La démonstration s'en écartait, et cet écart interdisait
     * le chaînage.
     */
    private fun preparerAppareil(cloudProjectNumber: Long): Pair<String, PlayIntegrity.Provider> {
        alias?.let { a -> provider?.let { p -> return a to p } }

        report("projet cloud   $cloudProjectNumber")
        var start = System.nanoTime()
        val p = PlayIntegrity.prepare(this, cloudProjectNumber)
        report("prepare        %.0f ms — une fois par lancement".format(ms(start)))

        // Le défi d'enrôlement doit survivre à la génération : le serveur le
        // confronte à celui que le TEE a inscrit dans l'extension
        // d'attestation. Le perdre rendrait la chaîne invérifiable.
        val a = "probative-session-${System.currentTimeMillis()}"
        val enrollChallenge = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        start = System.nanoTime()
        KeystoreKeys.generate(a, enrollChallenge)
        report("cle materielle ${KeystoreKeys.securityLevel(a)} en %.0f ms".format(ms(start)))

        val chain = KeystoreKeys.certificateChain(a)
        // En répétition, la chaîne n'est pas transmise : celle d'un émulateur
        // est cohérente mais ne s'ancre à aucune racine Google, et le serveur
        // la refuse — à raison. On enrôle alors sur parole pour exercer la
        // suite, et la bannière l'annonce.
        val enrolled = DevServer(BuildConfig.DEVSERVER_URL).enroll(
            KeystoreKeys.publicKeyX962(a),
            if (BuildConfig.REHEARSAL) null else chain,
            enrollChallenge,
        )
        report("enrolement     ${chain.size} certificats, kid ${enrolled.getString("kid_hex")}")
        report("               chaine attestee : ${enrolled.getBoolean("attested")}")
        report("               enrole une fois : c'est ce qui rend le chainage possible")

        alias = a
        provider = p
        return a to p
    }

    private fun sequence(cloudProjectNumber: Long) {
        val server = DevServer(BuildConfig.DEVSERVER_URL)
        val (alias, provider) = preparerAppareil(cloudProjectNumber)
        var start: Long

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
            // La seule ligne qui change entre les deux régimes : le reste du
            // chemin — R1, en-tête, signature — ignore d'où vient la fraîcheur.
            freshness = if (horsLigne) {
                KeyAttestationFreshness()
            } else {
                PlayIntegrityFreshness(provider)
            },
        )
        // Le maillon précédent, s'il existe. Première prise d'une série : rien
        // à chaîner, et le serveur le signale par `CHAIN_FIRST_LINK_UNKNOWN`.
        val precedent = dernierDigest
        val scelle = if (probe == Probe.CAPTURE) {
            scellerPhoto(sealer, nonce, precedent)
        } else {
            scellerOctets(sealer, nonce, precedent)
        }
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
        // Le maillon suivant chaînera sur celle-ci. Le serveur retient la même
        // empreinte de son côté (`DeviceRecord.last_envelope_digest`) : c'est
        // leur accord qui vaut vérification.
        dernierDigest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(scelle.sealed.bytes)
        consigner(result, scelle, KeystoreKeys.kid(alias).joinToString("") { "%02x".format(it) })
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
            serie = serie,
            profil = result.getString("profile"),
            niveau = result.getString("level"),
            motif = result.getString("level_reason"),
            // Le grade **et** son evidence. Le grade seul disait « origin B »
            // sans dire pourquoi ; or c'est dans l'evidence que se lit ce que
            // Google a réellement établi sur cette photo-là — `app-recognized`
            // pour le binaire, `play-integrity:r1-bound` pour la liaison à
            // cette charge utile.
            proprietes = proprietes.keys().asSequence().map {
                val propriete = proprietes.getJSONObject(it)
                "%-10s %s  %s".format(
                    it,
                    propriete.getString("grade"),
                    propriete.optString("evidence"),
                )
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
        prisesDansSerie += 1
        if (debutSerieMs == 0L) debutSerieMs = System.currentTimeMillis()
        report("")
        report("prise n°${prise.index} consignee — ${Historique.compte()} au tableau")
        report("serie $serie : $prisesDansSerie prise(s)")
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
    private fun scellerOctets(sealer: Sealer, nonce: ByteArray, prev: ByteArray?): Scelle {
        val start = System.nanoTime()
        val sealed = sealer.seal(CONTENT, CONTENT_TYPE, nonce, prevDigest = prev)
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
    private fun scellerPhoto(sealer: Sealer, nonce: ByteArray, prev: ByteArray?): Scelle {
        val start = System.nanoTime()
        // Partagée avec le viseur : à ce point un point de position est
        // normalement déjà là, et la moisson ne coûte rien.
        val capteurs = this.capteurs ?: Sensors.begin(this).also { this.capteurs = it }
        run {
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
            val sealed = sealer.seal(image, position, claims, nonce, prevDigest = prev)
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
        }
        // Plus de `capteurs.stop()` ici : la collecte survit à la capture et
        // sert la suivante. Elle est fermée avec l'écran (`onDestroy`).
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
        rafraichisseur.removeCallbacksAndMessages(null)
        // Un écouteur de position oublié vide la batterie et survit à l'écran.
        capteurs?.stop()
        capteurs = null
        alias?.let { if (KeystoreKeys.exists(it)) KeystoreKeys.delete(it) }
        alias = null
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
                setOnClickListener { montrerTableau() }
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
