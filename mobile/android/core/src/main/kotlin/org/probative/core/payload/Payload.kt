package org.probative.core.payload

/**
 * Construction de la charge utile du **noyau** (profil `core`, spec §2.5).
 *
 * Aucune dépendance Android ici : ce fichier est du calcul pur, ce qui le
 * rend vérifiable sur l'hôte contre les vecteurs d'or. La collecte, elle,
 * vit dans [DeviceState] et n'est exerçable que sur appareil.
 *
 * L'implémentation de référence reste `verifier-python/tests/factory.py` :
 * si ce code produit une charge utile que la fabrique ne saurait pas
 * produire, c'est ce code qui s'écarte de la spécification.
 */
object CorePayload {

    /** Profil déclaré dans l'en-tête protégé (label 102). */
    const val PROFILE = "core"

    /**
     * Assemble la charge utile. Les labels et leur obligation viennent de
     * `spec/envelope-v0.1.cddl` : 1, 2, 4 et 5 obligatoires, 7 optionnel.
     *
     * Ni `position` (3) ni corroboration (6) : le noyau n'affirme rien du
     * monde physique, et les ajouter ferait juste porter à l'enveloppe des
     * champs qu'aucune propriété ne note (drapeau `UNGRADED_FIELDS`).
     */
    fun build(
        nonce: ByteArray,
        media: Media,
        timing: Timing,
        posture: Posture,
        prevDigest: ByteArray? = null,
    ): Map<Int, Any> {
        require(nonce.isNotEmpty()) { "nonce vide" }
        val payload = mutableMapOf<Int, Any>(
            1 to nonce,
            2 to media.toCbor(),
            4 to timing.toCbor(),
            5 to posture.toCbor(),
        )
        if (prevDigest != null) {
            require(prevDigest.size == 32) { "chaînage : SHA-256 de 32 octets attendu" }
            payload[7] = prevDigest
        }
        return payload
    }
}

/**
 * Bloc `media` du noyau : ce que l'enveloppe dit des octets scellés.
 *
 * [digest] porte sur **les octets qui partiront au serveur**, jamais sur une
 * représentation intermédiaire — un décodage suivi d'un ré-encodage produirait
 * un `MEDIA_DIGEST_MISMATCH` dont la cause serait illisible.
 *
 * Les dimensions (label 5) et la durée (label 7) sont absentes à dessein :
 * elles relèvent du profil `capture`, pas du noyau.
 */
class Media(
    val digest: ByteArray,
    val mimeType: String,
    val sizeBytes: Long,
    val signLatencyMs: Long,
) {
    internal fun toCbor(): Map<Int, Any> {
        require(digest.size == 32) { "empreinte SHA-256 de 32 octets attendue" }
        require(mimeType.isNotBlank()) { "type MIME vide" }
        require(sizeBytes >= 0) { "taille négative" }
        require(signLatencyMs >= 0) { "latence négative" }
        return mapOf(
            1 to "sha-256",
            2 to digest,
            3 to mimeType,
            4 to sizeBytes,
            6 to signLatencyMs,
        )
    }
}

/**
 * Bloc `timing` : les trois horloges, plus l'état de synchronisation.
 *
 * [wallMs] est falsifiable — c'est tout l'objet de R3 côté serveur, qui la
 * confronte à l'émission du nonce. On la transmet quand même : le serveur ne
 * peut mesurer l'écart que s'il voit ce que l'appareil croyait être l'heure.
 */
class Timing(
    val wallMs: Long,
    val elapsedRealtimeMs: Long,
    val utcOffsetMinutes: Int,
    val automaticTime: Boolean? = null,
) {
    internal fun toCbor(): Map<Int, Any> {
        val timing = mutableMapOf<Int, Any>(
            1 to wallMs,
            2 to elapsedRealtimeMs,
            3 to utcOffsetMinutes,
        )
        if (automaticTime != null) timing[4] = automaticTime
        return timing
    }
}

/**
 * Bloc `posture` : l'état déclaré de l'appareil.
 *
 * **Déclaratif, donc faible** — le client collecte, le serveur juge
 * (invariant 1). Aucune de ces valeurs ne conditionne quoi que ce soit ici.
 *
 * Les champs optionnels valent `null` quand la mesure n'a **pas été faite**,
 * et ils sont alors omis de l'encodage. Émettre `false` reviendrait à
 * affirmer « j'ai regardé, il n'y a rien » : c'est exactement la réclamation
 * simulée que la règle d'A6 interdit, et le serveur n'aurait aucun moyen de
 * distinguer les deux.
 */
class Posture(
    val platform: String,
    val osVersion: String,
    val appVersion: String,
    val debuggerAttached: Boolean,
    val emulatorSuspected: Boolean,
    val developerMode: Boolean? = null,
    val mockLocation: Boolean? = null,
    val suspiciousPackages: List<String>? = null,
) {
    internal fun toCbor(): Map<Int, Any> {
        require(platform == "android" || platform == "ios") { "plateforme inconnue : $platform" }
        val posture = mutableMapOf<Int, Any>(
            1 to platform,
            2 to osVersion,
            3 to appVersion,
            4 to debuggerAttached,
            5 to emulatorSuspected,
        )
        if (developerMode != null) posture[6] = developerMode
        if (mockLocation != null) posture[7] = mockLocation
        if (suspiciousPackages != null) posture[8] = suspiciousPackages
        return posture
    }
}
