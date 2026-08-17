package org.probative.core.payload

/**
 * Construction de la charge utile du profil **`capture`** (spec §2.5).
 *
 * Le noyau plus trois exigences : une [Position], une description du médium
 * (`media[5]` **ou** `media[7]`), et la corroboration qui rend la position
 * défendable. En échange une propriété de plus est notée — et un plafond
 * s'applique : `origin` ne dépasse pas B tant que la recapture analogique n'est
 * pas détectée (ADR-0005).
 *
 * Comme [CorePayload], du calcul pur : aucune dépendance Android, donc
 * vérifiable sur l'hôte contre le vecteur d'or `ios`, qui est un vecteur de
 * profil et non de plateforme.
 */
object CapturePayload {

    /** Profil déclaré dans l'en-tête protégé (label 102). */
    const val PROFILE = "capture"

    /**
     * Assemble la charge utile d'une acquisition.
     *
     * Les [claims] ne sont pas décoratives. Sur Android l'indicateur de
     * position simulée existe (`posture[7]`), ce qui dispense de la
     * contrepartie inertielle qu'iOS doit fournir — mais la réclamation
     * `baro-alt` reste le signal le plus rentable des deux plateformes, parce
     * qu'un simulateur de GNSS ne falsifie jamais la pression atmosphérique.
     */
    fun build(
        nonce: ByteArray,
        media: Media,
        position: Position,
        timing: Timing,
        posture: Posture,
        claims: List<Claim> = emptyList(),
        prevDigest: ByteArray? = null,
    ): Map<Int, Any> {
        require(nonce.isNotEmpty()) { "nonce vide" }
        // Faute d'appelant, pas d'attaquant : le serveur la rejetterait, mais
        // bien plus tard et avec un motif moins lisible qu'ici.
        require(media.describesMedium) {
            "profil capture : media[5] (dimensions) ou media[7] (durée) exigé"
        }
        val payload = mutableMapOf<Int, Any>(
            1 to nonce,
            2 to media.toCbor(),
            3 to position.toCbor(),
            4 to timing.toCbor(),
            5 to posture.toCbor(),
        )
        // Le CDDL veut `[+ claim]` : une liste présente est non vide. Aucune
        // mesure obtenue s'omet, plutôt que d'encoder un tableau vide qui
        // affirmerait avoir cherché sans rien trouver — la réclamation simulée
        // que la règle d'A6 interdit.
        if (claims.isNotEmpty()) {
            payload[6] = claims.map { it.toCbor() }
        }
        if (prevDigest != null) {
            require(prevDigest.size == 32) { "chaînage : SHA-256 de 32 octets attendu" }
            payload[7] = prevDigest
        }
        return payload
    }
}

/**
 * Bloc `position` : où le cœur croyait être **au déclenchement**.
 *
 * [fixAgeMs] est un **âge**, pas un horodatage : l'écart entre l'instant du
 * point et celui de l'obturateur. Il faut donc conserver les deux instants pour
 * le calculer, ce qu'un champ d'horodatage seul n'aurait pas permis. Au-delà du
 * seuil de politique, le point ne prouve plus rien sur l'instant de la capture.
 */
class Position(
    val latitude: Double,
    val longitude: Double,
    val horizontalAccuracy: Double,
    val provider: Provider,
    val fixAgeMs: Long,
    val altitude: Double? = null,
    val verticalAccuracy: Double? = null,
    /**
     * Nombre de satellites (label 8) — **qu'Android expose et pas iOS**.
     *
     * L'écart est absorbé par le format, qui laisse le label optionnel : c'est
     * l'invariant 4 en pratique. L'inventer côté iOS serait une réclamation
     * simulée ; l'omettre côté Android serait perdre une mesure réelle.
     */
    val satellites: Int? = null,
) {
    /**
     * Origine du point. Le format ferme la liste : un fournisseur inconnu se
     * déclare [UNKNOWN] plutôt que de s'inventer un nom, sans quoi le serveur
     * devrait tenir un registre de chaînes libres.
     */
    enum class Provider(val label: String) {
        GNSS("gnss"),
        FUSED("fused"),
        NETWORK("network"),
        UNKNOWN("unknown"),
    }

    internal fun toCbor(): Map<Int, Any> {
        require(fixAgeMs >= 0) { "âge de point négatif" }
        val position = mutableMapOf<Int, Any>(
            1 to latitude,
            2 to longitude,
            3 to horizontalAccuracy,
            6 to provider.label,
            7 to fixAgeMs,
        )
        if (altitude != null) position[4] = altitude
        if (verticalAccuracy != null) position[5] = verticalAccuracy
        if (satellites != null) {
            require(satellites >= 0) { "nombre de satellites négatif" }
            position[8] = satellites
        }
        return position
    }
}

/**
 * Une mesure de corroboration (spec §2.4) — extensible par construction : le
 * cœur ne connaît aucun type de réclamation en particulier, et le vérificateur
 * ignore ceux qu'il ne sait pas lire (drapeau `UNKNOWN_CLAIMS`).
 *
 * [value] est libre par le format (`any` au CDDL). Deux conventions valent
 * pourtant d'être tenues, parce que le serveur les compare :
 *
 * - **`baro-alt` est en mètres**, pour être confrontable à `position[4]` ;
 * - **`baro` est en hectopascals**, l'unité que rend nativement Android
 *   (`Sensor.TYPE_PRESSURE`). iOS donne des kilopascals et doit convertir.
 *
 * Une unité se corrige par un **nouveau type**, jamais par redéfinition : un
 * type inconnu est ignoré en silence, là où un type mal lu ne l'est pas
 * (spec §2.4).
 */
class Claim(
    val type: String,
    val source: String,
    val uptimeMs: Long,
    val value: Any,
) {
    internal fun toCbor(): Map<Int, Any> {
        require(type.isNotBlank()) { "type de réclamation vide" }
        require(uptimeMs >= 0) { "horodatage monotone négatif" }
        return mapOf(
            1 to type,
            2 to source,
            3 to uptimeMs,
            4 to value,
        )
    }
}
