package org.probative.core.sensors

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.location.GnssStatus
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import org.probative.core.payload.Claim
import org.probative.core.payload.Position
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Collecte de la position et des réclamations de corroboration.
 *
 * **La forme importe autant que le contenu.** [begin] démarre les capteurs et
 * rend la main immédiatement ; la moisson n'a lieu qu'à [SensorRun.position] et
 * [SensorRun.claims]. C'est ce qui permet à l'appelant de faire courir la
 * collecte **pendant** l'acquisition photographique, et ce n'est pas une
 * élégance : la jointure se situe après l'obturateur, donc tout capteur qui
 * survit à la capture verse son excédent dans `media[6]` — le champ noté. Une
 * collecte lancée après la photo a coûté **+4,2 s** dans ce champ côté iOS,
 * faisant accuser une latence anormale là où il n'y en avait aucune.
 *
 * **Rien n'est simulé.** Un capteur absent, une autorisation refusée ou une
 * mesure qui n'arrive pas produisent une réclamation **omise**, jamais une
 * valeur par défaut. Émettre zéro ou `false` affirmerait « j'ai regardé, il n'y
 * a rien », que le serveur ne saurait pas distinguer d'une mesure réelle. C'est
 * la règle d'A6, et elle vaut aussi pour la position, qui peut être `null`.
 *
 * Le cœur ne demande aucune autorisation : il constate. Le préambule de
 * l'application les a obtenues avant la première mesure — ou pas, et la
 * collecte le dit en ne rendant rien.
 */
object Sensors {

    /** Fenêtre de mouvement, alignée sur la convention de la spec §2.4. */
    const val MOTION_WINDOW_MS = 10_000L

    /**
     * Au-delà, un point ne prouve plus rien sur l'instant de la capture. Le
     * seuil de notation côté serveur est à 15 s (`max_fix_age_ms`) ; on vise
     * plus serré pour ne pas rendre systématiquement un point limite.
     */
    const val MAX_FIX_AGE_MS = 10_000L

    /** Bornes de l'attente d'un point. Un premier point GNSS peut être long. */
    const val FIX_TIMEOUT_MS = 8_000L

    /**
     * Démarre la collecte et rend la main **tout de suite**.
     *
     * L'appelant enchaîne sur l'acquisition, puis moissonne. Voir
     * [SensorRun.stop], qui doit être appelé dans tous les cas — un écouteur
     * de position oublié vide la batterie et survit à la sonde.
     */
    fun begin(context: Context): SensorRun {
        val thread = HandlerThread("probative-sensors").apply { start() }
        val handler = Handler(thread.looper)
        val run = SensorRun(context, thread, handler)
        run.start()
        return run
    }

    internal fun hasLocationPermission(context: Context): Boolean =
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED ||
            context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
}

/**
 * Une collecte en cours. Créée par [Sensors.begin], moissonnée après
 * l'acquisition, et fermée par [stop] dans tous les cas.
 */
class SensorRun internal constructor(
    private val context: Context,
    private val thread: HandlerThread,
    private val handler: Handler,
) {

    private val locationManager =
        context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
    private val sensorManager =
        context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager

    @Volatile private var meilleurPoint: Location? = null
    private val premierPoint = CountDownLatch(1)

    @Volatile private var satellitesUtilises: Int? = null

    /** Dernière pression lue, en hectopascals — l'unité native d'Android. */
    @Volatile private var pressionHpa: Double? = null
    @Volatile private var pressionUptimeMs: Long = 0

    /** Échantillons d'accélération : (uptime ms, x, y, z) en m/s². */
    private val mouvement = ArrayList<DoubleArray>()
    private val verrouMouvement = Any()

    private val ecouteurPosition = object : LocationListener {
        override fun onLocationChanged(location: Location) {
            // On garde le plus précis, pas le plus récent : un point réseau
            // arrive vite et grossier, le point GNSS suit et vaut mieux.
            val courant = meilleurPoint
            if (courant == null || location.accuracy <= courant.accuracy) {
                meilleurPoint = location
            }
            premierPoint.countDown()
        }

        @Deprecated("obligatoire avant API 30, sans objet ici")
        override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) = Unit
    }

    private val ecouteurGnss = object : GnssStatus.Callback() {
        override fun onSatelliteStatusChanged(status: GnssStatus) {
            var utilises = 0
            for (i in 0 until status.satelliteCount) {
                if (status.usedInFix(i)) utilises++
            }
            satellitesUtilises = utilises
        }
    }

    private val ecouteurCapteurs = object : SensorEventListener {
        override fun onSensorChanged(event: SensorEvent) {
            val maintenant = SystemClock.elapsedRealtime()
            when (event.sensor.type) {
                Sensor.TYPE_PRESSURE -> {
                    pressionHpa = event.values[0].toDouble()
                    pressionUptimeMs = maintenant
                }
                Sensor.TYPE_ACCELEROMETER -> synchronized(verrouMouvement) {
                    // Borné : une fenêtre de 10 s à la cadence normale tient en
                    // quelques dizaines d'échantillons, mais un capteur bavard
                    // gonflerait la charge utile sans rien ajouter.
                    if (mouvement.size < 64) {
                        mouvement.add(
                            doubleArrayOf(
                                maintenant.toDouble(),
                                event.values[0].toDouble(),
                                event.values[1].toDouble(),
                                event.values[2].toDouble(),
                            ),
                        )
                    }
                }
            }
        }

        override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
    }

    internal fun start() {
        demarrerPosition()
        demarrerCapteurs()
    }

    private fun demarrerPosition() {
        val manager = locationManager ?: return
        if (!Sensors.hasLocationPermission(context)) return
        // Deux fournisseurs plutôt qu'un : le réseau donne un point tout de
        // suite, le GNSS donne le bon. `meilleurPoint` arbitre à la précision.
        val fournisseurs = buildList {
            if (manager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                add(LocationManager.GPS_PROVIDER)
            }
            if (manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                add(LocationManager.NETWORK_PROVIDER)
            }
        }
        for (fournisseur in fournisseurs) {
            try {
                manager.requestLocationUpdates(fournisseur, 0L, 0f, ecouteurPosition, thread.looper)
            } catch (_: SecurityException) {
                // L'autorisation a pu tomber entre le contrôle et l'appel.
                // Omettre plutôt qu'échouer : la position sera simplement nulle.
            }
        }
        try {
            manager.registerGnssStatusCallback(ecouteurGnss, handler)
        } catch (_: SecurityException) {
            // Le nombre de satellites restera absent, ce que le format admet.
        }
    }

    private fun demarrerCapteurs() {
        val manager = sensorManager ?: return
        // Ni l'un ni l'autre ne demande d'autorisation sur Android — c'est ce
        // que le préambule affiche en « mouvement : non requise », et l'écart
        // avec iOS qui exige une autorisation de mouvement pour le baromètre.
        manager.getDefaultSensor(Sensor.TYPE_PRESSURE)?.let {
            manager.registerListener(ecouteurCapteurs, it, SensorManager.SENSOR_DELAY_NORMAL, handler)
        }
        manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)?.let {
            manager.registerListener(ecouteurCapteurs, it, SensorManager.SENSOR_DELAY_NORMAL, handler)
        }
    }

    /**
     * Attend un point exploitable et le convertit, **l'obturateur servant
     * d'origine**.
     *
     * `fixAgeMs` est l'écart entre l'instant du point et celui de
     * l'obturateur — un âge, pas un horodatage. Les deux instants vivent sur
     * `elapsedRealtime`, la même horloge que `media[6]` : c'est ce qui rend la
     * soustraction licite.
     *
     * Rend `null` si aucun point n'arrive, si l'autorisation manque, ou si le
     * seul point disponible est trop vieux. Un `null` est une **omission**, pas
     * un échec : le serveur rejettera l'enveloppe `capture` faute de position,
     * avec un motif lisible, et c'est préférable à une position inventée.
     */
    fun position(shutterElapsedMs: Long, timeoutMs: Long = Sensors.FIX_TIMEOUT_MS): Position? {
        if (meilleurPoint == null) {
            premierPoint.await(timeoutMs, TimeUnit.MILLISECONDS)
        }
        val point = meilleurPoint ?: return null

        val pointElapsedMs = point.elapsedRealtimeNanos / 1_000_000
        val age = shutterElapsedMs - pointElapsedMs
        // Un point postérieur à l'obturateur arrive : la collecte court pendant
        // l'acquisition, c'est même le but. Son âge est alors nul, pas négatif.
        val ageMs = if (age < 0) 0L else age
        if (ageMs > Sensors.MAX_FIX_AGE_MS) return null

        return Position(
            latitude = point.latitude,
            longitude = point.longitude,
            horizontalAccuracy = point.accuracy.toDouble(),
            provider = fournisseur(point),
            fixAgeMs = ageMs,
            altitude = if (point.hasAltitude()) point.altitude else null,
            verticalAccuracy = verticale(point),
            satellites = satellitesUtilises,
        )
    }

    /**
     * Les réclamations collectées. Aucune mesure obtenue rend une liste vide,
     * qui sera **omise** de la charge utile plutôt qu'encodée vide.
     *
     * `baro-alt` est dérivée de la pression et non lue ailleurs : c'est une
     * altitude **absolue** en mètres, seule forme confrontable à `position[4]`.
     * Une altitude relative n'aurait jamais pu correspondre — l'erreur a été
     * commise côté iOS et corrigée en rendant les unités normatives (spec §2.4).
     */
    fun claims(): List<Claim> {
        val liste = mutableListOf<Claim>()

        val pression = pressionHpa
        if (pression != null) {
            liste.add(Claim("baro", "barometer", pressionUptimeMs, pression))
            // `getAltitude` rend des mètres au-dessus du niveau de la mer, à
            // partir de l'atmosphère standard : absolue, donc comparable.
            val altitude = SensorManager.getAltitude(
                SensorManager.PRESSURE_STANDARD_ATMOSPHERE,
                pression.toFloat(),
            ).toDouble()
            liste.add(Claim("baro-alt", "barometer", pressionUptimeMs, altitude))
        }

        val echantillons = synchronized(verrouMouvement) { mouvement.toList() }
        if (echantillons.isNotEmpty()) {
            val origine = echantillons.first()[0]
            val fenetre = echantillons
                .filter { it[0] - origine <= Sensors.MOTION_WINDOW_MS }
                // Le premier terme est un décalage relatif en ms, pas un
                // horodatage : c'est la forme du vecteur d'or.
                .map { listOf((it[0] - origine).toLong(), it[1], it[2], it[3]) }
            liste.add(Claim("motion", "accelerometer", origine.toLong(), fenetre))
        }

        // Pas de `steps` : le podomètre exige `ACTIVITY_RECOGNITION`, que la
        // démonstration ne déclare pas. L'omettre est la règle ; le simuler
        // serait la faute. Sans conséquence sur la note, l'indicateur de
        // position simulée d'Android tenant lieu de contrepoids là où iOS
        // dépend de la corroboration inertielle.
        return liste
    }

    /** Libère capteurs et fil. À appeler dans tous les cas. */
    fun stop() {
        try {
            locationManager?.removeUpdates(ecouteurPosition)
            locationManager?.unregisterGnssStatusCallback(ecouteurGnss)
        } catch (_: SecurityException) {
            // Rien à libérer si rien n'a été enregistré.
        }
        sensorManager?.unregisterListener(ecouteurCapteurs)
        thread.quitSafely()
    }

    private fun fournisseur(point: Location): Position.Provider = when (point.provider) {
        LocationManager.GPS_PROVIDER -> Position.Provider.GNSS
        LocationManager.NETWORK_PROVIDER -> Position.Provider.NETWORK
        LocationManager.FUSED_PROVIDER -> Position.Provider.FUSED
        else -> Position.Provider.UNKNOWN
    }

    private fun verticale(point: Location): Double? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && point.hasVerticalAccuracy()) {
            point.verticalAccuracyMeters.toDouble()
        } else {
            null
        }
}
