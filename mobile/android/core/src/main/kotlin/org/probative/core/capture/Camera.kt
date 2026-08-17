package org.probative.core.capture

import android.content.Context
import android.graphics.ImageFormat
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.lifecycle.LifecycleOwner
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Format des octets acquis — **déclaré par ce qui a réellement été encodé**,
 * jamais par une chaîne parallèle.
 *
 * Le piège que ferme ADR-0007 point 3 : un codec configuré d'un côté et un type
 * MIME écrit en dur de l'autre finissent par diverger, et l'enveloppe déclare
 * alors un type faux — signé, opposable, et que rien ne voit. Le vérificateur
 * ne peut pas le rattraper, l'invariant 6 lui interdisant de connaître le type
 * de contenu.
 *
 * D'où [fromImageFormat] : le format est **lu sur les octets rendus**, et une
 * valeur inattendue arrête l'acquisition au lieu de la laisser mentir.
 */
enum class CaptureFormat(val mimeType: String) {

    /**
     * JPEG — le défaut de `ImageCapture`, et un choix motivé plutôt qu'hérité.
     *
     * Il se paie en taille et en finesse du résidu de bruit de capteur, si
     * l'empreinte PRNU devenait un jour exploitable. L'argument est
     * l'**opposabilité** : une pièce destinée à être opposée dans dix ans se
     * conserve dans le format qu'on saura ouvrir dans dix ans. ADR-0007
     * points 1 et 7.
     */
    JPEG("image/jpeg"),
    ;

    internal companion object {
        fun fromImageFormat(format: Int): CaptureFormat? = when (format) {
            ImageFormat.JPEG -> JPEG
            else -> null
        }
    }
}

/**
 * Décomposition du temps d'acquisition, en six bornes sur l'horloge monotone.
 *
 * Elle existe pour une raison mesurée : côté iOS, deux campagnes identiques sur
 * le même iPhone 16 ont rendu 1 904 ms puis 2 494 ms sans qu'on puisse dire
 * *où*. Or les termes n'ont ni la même nature ni le même remède — la mise sous
 * tension du capteur est structurelle et disparaît avec un aperçu vivant, la
 * convergence 3A dépend de la scène et ne se corrige pas, l'encodage dépend du
 * format demandé. **Une somme ne se pilote pas.**
 *
 * **Une seule de ces bornes entre dans `media[6]`.** Le champ noté part de
 * l'obturateur : tout ce qui précède mesure le coût du client, tout ce qui suit
 * mesure le chemin capteur→charge utile. Les avoir confondus a fait croire la
 * marge contre `max_sign_latency_ms` plus mince qu'elle n'est.
 *
 * **Toutes les bornes sont sur `SystemClock.elapsedRealtimeNanos`**, et ce
 * n'est pas indifférent : c'est la même horloge que celle qu'attend
 * `Sealer.seal(acquiredAtElapsedMs = …)`. Un mélange d'horloges y produirait un
 * `media[6]` absurde — grand, négatif, ou pire, plausible.
 *
 * Sur une session **longue**, les quatre premières bornes décrivent l'ouverture
 * de la session et non la photo : elles sont partagées par toutes les prises de
 * cette session. C'est précisément ce que la décomposition doit montrer — leur
 * caractère structurel.
 */
class CaptureTimings(
    /** Entrée dans l'ouverture de session. */
    val startNanos: Long,
    /** Cas d'usage construits et liés : le périphérique est ouvert. */
    val configuredNanos: Long,
    /** La caméra diffuse — capteur sous tension. */
    val runningNanos: Long,
    /** Fin du délai de garde tenu par le cœur. */
    val armedNanos: Long,
    /** Obturateur. **L'origine de `media[6]`** : rien de ce qui précède n'y entre. */
    val shutterNanos: Long,
    /** Octets encodés disponibles. */
    val deliveredNanos: Long,
) {

    /** Ouverture du périphérique et liaison des cas d'usage. */
    val configureMs: Long get() = ms(startNanos, configuredNanos)

    /**
     * Mise sous tension du capteur. **Payée à chaque photo en session
     * éphémère**, une seule fois en session longue — c'est le terme qu'un
     * aperçu vivant fait disparaître de la latence perçue.
     */
    val startupMs: Long get() = ms(configuredNanos, runningNanos)

    /**
     * Le délai de garde en dur du cœur. Constant par construction, donc sans
     * intérêt en soi — c'est le **témoin** : s'il s'écarte de sa consigne, une
     * file était saturée et les autres bornes ne sont pas lisibles.
     */
    val settleMs: Long get() = ms(runningNanos, armedNanos)

    /**
     * Convergence 3A avant déclenchement, à la main de CameraX. Le terme qui
     * dépend de la scène : lumière faible, autofocus qui cherche.
     */
    val shutterLagMs: Long get() = ms(armedNanos, shutterNanos)

    /** Traitement et encodage. **Le seul terme qui pèse dans `media[6]`.** */
    val encodeMs: Long get() = ms(shutterNanos, deliveredNanos)

    /** Le total — ce qu'une sonde rapporterait seule sans cette décomposition. */
    val totalMs: Long get() = ms(startNanos, deliveredNanos)

    /**
     * L'instant de l'obturateur, sur l'horloge et dans l'unité qu'attend
     * `Sealer.seal`. C'est le seul champ de cette classe qui sorte du
     * diagnostic pour entrer dans l'enveloppe.
     */
    val shutterElapsedMs: Long get() = shutterNanos / 1_000_000

    private fun ms(from: Long, to: Long): Long = (to - from) / 1_000_000
}

/**
 * Ce que rend une acquisition photographique.
 *
 * [bytes] porte **les octets tels que le pipeline photo les a produits**, et
 * [format] dit dans quel encodage — les deux voyagent ensemble pour que le type
 * MIME de l'enveloppe ne puisse pas contredire ce qui a été encodé.
 *
 * Le champ ne se nomme pas d'après son format : le nommer `jpeg` graverait
 * l'encodage dans une API publique et ferait d'un futur changement une rupture
 * d'interface, alors que `media[3]` est déclaré par capture. ADR-0007 point 2.
 *
 * **Ne jamais ré-encoder.** Décoder en `Bitmap` puis ré-encoder change les
 * octets, et le serveur rejetterait en `MEDIA_DIGEST_MISMATCH` sans que la
 * cause soit lisible. On hache ce tampon tel quel, et on envoie ce même tampon.
 *
 * La règle ne s'arrête pas à la sortie du cœur. L'enveloppe ne portant qu'une
 * **empreinte**, ces octets-là doivent être archivés intacts : recompression,
 * nettoyage d'EXIF, redimensionnement ou normalisation d'orientation rompent la
 * liaison sans rattrapage possible. Les dérivés se fabriquent à côté, jamais à
 * la place. ADR-0007 points 4 et 5, spec §2.3.
 */
class CapturedImage(
    val bytes: ByteArray,
    val format: CaptureFormat,
    val pixelWidth: Int,
    val pixelHeight: Int,
    /**
     * Où le temps est passé. Diagnostic seul : rien de ce que porte ce champ
     * n'entre dans l'enveloppe, sauf [shutterElapsedMs].
     */
    val timings: CaptureTimings,
) {
    /**
     * Instant de l'obturateur — l'origine de `media[6]`, et la référence de
     * l'âge du point de position.
     */
    val shutterElapsedMs: Long get() = timings.shutterElapsedMs
}

/** Échec d'acquisition. Le cœur ne juge pas : il rend les octets ou il lève. */
class CameraException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Session de capture — **possédée par le cœur**, conformément à ADR-0008.
 *
 * La décision qu'incarne cette classe : le cœur détient la liaison CameraX et
 * lie lui-même `Preview` et `ImageCapture`. Une application qui veut afficher un
 * aperçu ne crée pas sa propre session, elle **rattache la sienne à celle-ci**
 * par [attachPreview]. Deux sessions concurrentes se disputeraient la caméra —
 * mode de défaillance prévisible de toute intégration naïve.
 *
 * **Le cœur ne dessine rien.** L'affichage — la vue, sa taille, sa place, les
 * superpositions, le bouton déclencheur — appartient entièrement à
 * l'application. Le cœur possède la source, l'application possède la fenêtre
 * ouverte dessus. C'est aussi ce qui permet à l'AAR de ne dépendre ni de
 * `camera-view` ni d'`android.view`, condition d'ADR-0003.
 *
 * Pourquoi le cœur et pas la vue : le profil `capture` n'affirme qu'une chose —
 * le cœur a **observé** l'acquisition (spec §2.5). Une session possédée par
 * l'hôte lui laisserait choisir la sortie, le format, voire la source, et le
 * cœur signerait des octets dont il n'a pas vu la naissance.
 *
 * **Deux durées de vie, une seule forme.** [Camera.capture] ouvre une session le
 * temps d'une photo ; un appelant qui veut un aperçu garde la sienne ouverte.
 * Ce n'est pas deux modes, c'est la même session vécue plus ou moins longtemps.
 *
 * Toutes les méthodes sont **bloquantes** et ne doivent jamais être appelées sur
 * le fil principal — la liaison CameraX, elle, y est postée en interne.
 */
class CaptureSession private constructor(
    private val provider: ProcessCameraProvider,
    private val preview: Preview,
    private val imageCapture: ImageCapture,
    private val executor: Executor,
    private val stamps: OpenStamps,
) {

    internal class OpenStamps(
        val start: Long,
        val configured: Long,
        val running: Long,
        val armed: Long,
    )

    /**
     * Rattache un aperçu. L'application fournit le `SurfaceProvider` de sa
     * propre vue — typiquement `PreviewView.getSurfaceProvider()`, la vue
     * vivant dans son module à elle.
     */
    fun attachPreview(surfaceProvider: Preview.SurfaceProvider) {
        onMain { preview.surfaceProvider = surfaceProvider }
    }

    /** Détache l'aperçu sans fermer la session. */
    fun detachPreview() {
        onMain { preview.surfaceProvider = null }
    }

    /**
     * Déclenche une photo et rend ses octets.
     *
     * L'obturateur est estampillé dans `onCaptureStarted`, **jamais à l'appel** :
     * la convergence 3A court entre les deux, et l'inclure dans `media[6]`
     * ferait accuser une latence de scellement là où il n'y a qu'un autofocus
     * qui cherche.
     */
    fun capture(): CapturedImage {
        requireNotMainThread()
        val boite = ArrayBlockingQueue<Result<CapturedImage>>(1)

        onMain {
            imageCapture.takePicture(
                executor,
                object : ImageCapture.OnImageCapturedCallback() {

                    private var shutter: Long = 0

                    override fun onCaptureStarted() {
                        shutter = SystemClock.elapsedRealtimeNanos()
                    }

                    override fun onCaptureSuccess(image: ImageProxy) {
                        boite.put(runCatching { image.use { lire(it, shutter) } })
                    }

                    override fun onError(exception: ImageCaptureException) {
                        boite.put(
                            Result.failure(
                                CameraException("capture refusée par CameraX", exception),
                            ),
                        )
                    }
                },
            )
        }
        return boite.take().getOrThrow()
    }

    /** Libère la caméra. La session n'est plus utilisable après cet appel. */
    fun close() {
        onMain { provider.unbindAll() }
    }

    /**
     * Lit les octets **tels quels**, et refuse un format inattendu.
     *
     * Le refus n'est pas de la rigueur gratuite : rendre des octets HEIC en les
     * déclarant `image/jpeg` produirait une enveloppe signée qui ment sur son
     * contenu, et rien en aval ne pourrait le voir.
     */
    private fun lire(image: ImageProxy, shutterNanos: Long): CapturedImage {
        val format = CaptureFormat.fromImageFormat(image.format)
            ?: throw CameraException(
                "format d'image inattendu (${image.format}) : le type MIME déclaré " +
                    "ne pourrait plus être celui des octets",
            )
        // Un seul plan pour du JPEG, et aucun ré-encodage : ce tampon est celui
        // que le pipeline photo a produit, c'est lui qu'on hache et lui qu'on
        // transmet.
        val tampon = image.planes[0].buffer
        val octets = ByteArray(tampon.remaining())
        tampon.get(octets)

        return CapturedImage(
            bytes = octets,
            format = format,
            pixelWidth = image.width,
            pixelHeight = image.height,
            timings = CaptureTimings(
                startNanos = stamps.start,
                configuredNanos = stamps.configured,
                runningNanos = stamps.running,
                armedNanos = stamps.armed,
                shutterNanos = shutterNanos,
                deliveredNanos = SystemClock.elapsedRealtimeNanos(),
            ),
        )
    }

    companion object {

        /**
         * Délai de garde après mise sous tension, avant d'autoriser une prise.
         *
         * En dur, et c'est assumé : c'est un **témoin**, pas un réglage. Sa
         * valeur importe moins que sa constance — un `settleMs` qui s'écarte de
         * cette consigne signale une file saturée, donc des autres bornes
         * illisibles.
         */
        const val SETTLE_MS = 400L

        /**
         * Ouvre une session et attend qu'elle soit prête à déclencher.
         *
         * [lifecycleOwner] vient de l'application : CameraX lie ses cas d'usage
         * à un cycle de vie, et c'est l'hôte qui en possède un. Le cœur décide
         * **ce qui est lié** ; l'hôte fournit seulement la portée.
         */
        fun open(
            context: Context,
            lifecycleOwner: LifecycleOwner,
            lensFacing: Int = CameraSelector.LENS_FACING_BACK,
        ): CaptureSession {
            requireNotMainThread()
            val start = SystemClock.elapsedRealtimeNanos()

            val provider = try {
                ProcessCameraProvider.getInstance(context).get()
            } catch (e: Exception) {
                throw CameraException("fournisseur CameraX indisponible", e)
            }

            val preview = Preview.Builder().build()
            // Aucun `setOutputFormat` : le format n'est pas *demandé* puis
            // supposé, il est **lu** sur les octets rendus (ADR-0007 point 3).
            // Une chaîne parallèle est exactement ce qu'on ferme ici.
            val imageCapture = ImageCapture.Builder()
                .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
                .build()
            val selector = CameraSelector.Builder().requireLensFacing(lensFacing).build()

            val configured: Long
            try {
                onMain {
                    provider.unbindAll()
                    provider.bindToLifecycle(lifecycleOwner, selector, preview, imageCapture)
                }
                configured = SystemClock.elapsedRealtimeNanos()
            } catch (e: Exception) {
                throw CameraException("liaison CameraX refusée", e)
            }

            // CameraX ne rend pas la main sur « le capteur diffuse » ; la
            // liaison revenue, la mise sous tension est en cours. On confond
            // donc `running` et `configured`, et on le dit plutôt que de
            // fabriquer une borne qu'on ne mesure pas.
            val running = configured
            Thread.sleep(SETTLE_MS)
            val armed = SystemClock.elapsedRealtimeNanos()

            return CaptureSession(
                provider = provider,
                preview = preview,
                imageCapture = imageCapture,
                executor = Executors.newSingleThreadExecutor(),
                stamps = OpenStamps(start, configured, running, armed),
            )
        }

        private fun requireNotMainThread() {
            check(Looper.myLooper() != Looper.getMainLooper()) {
                "acquisition bloquante appelée sur le fil principal"
            }
        }

        private fun <T> onMain(block: () -> T): T {
            if (Looper.myLooper() == Looper.getMainLooper()) return block()
            val boite = ArrayBlockingQueue<Result<T>>(1)
            Handler(Looper.getMainLooper()).post { boite.put(runCatching(block)) }
            return boite.take().getOrThrow()
        }
    }
}

/**
 * Acquisition d'une prise isolée — la session éphémère d'ADR-0008 point 2.
 *
 * Strictement une [CaptureSession] dont la vie tient dans l'appel. C'est ce que
 * fait le cœur iOS depuis C4.2, et le conserver garde les deux plateformes
 * comparables : un appelant sans aperçu paie la mise sous tension à chaque
 * photo, et `CaptureTimings` le montre terme à terme.
 */
object Camera {

    fun capture(
        context: Context,
        lifecycleOwner: LifecycleOwner,
        lensFacing: Int = CameraSelector.LENS_FACING_BACK,
    ): CapturedImage {
        val session = CaptureSession.open(context, lifecycleOwner, lensFacing)
        return try {
            session.capture()
        } finally {
            session.close()
        }
    }
}
