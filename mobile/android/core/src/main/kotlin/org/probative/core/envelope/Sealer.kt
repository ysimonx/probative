package org.probative.core.envelope

import android.content.Context
import android.os.SystemClock
import org.probative.core.capture.CapturedImage
import org.probative.core.cbor.Cbor
import org.probative.core.cose.Cose
import org.probative.core.freshness.FreshnessSource
import org.probative.core.keys.KeystoreKeys
import org.probative.core.payload.CapturePayload
import org.probative.core.payload.Claim
import org.probative.core.payload.CorePayload
import org.probative.core.payload.DeviceState
import org.probative.core.payload.Media
import org.probative.core.payload.Position
import java.security.MessageDigest

/**
 * Ce que rend un scellement. L'appelant n'a besoin que de [bytes] ; le reste
 * existe pour le diagnostic et pour les sondes, qui doivent pouvoir montrer
 * le défi qu'elles ont soumis sans le recalculer à leur façon — recalculer
 * est justement ce qui laisse les deux côtés diverger en silence.
 */
class SealedEnvelope(
    val bytes: ByteArray,
    val payloadBytes: ByteArray,
    val challenge: ByteArray,
    val mediaDigest: ByteArray,
    /**
     * La valeur de `media[6]` **telle qu'elle a été scellée**, en
     * millisecondes.
     *
     * Remontée plutôt que laissée enfouie dans la charge utile pour la même
     * raison que [challenge] : une sonde n'avait aucun moyen de la dire, et
     * la recalculer avec son propre chronomètre en rendrait une *autre* —
     * plus grande, puisqu'elle engloberait l'appel lui-même, et fausse.
     *
     * C'est le seul chiffre de latence que le vérificateur confronte à
     * `max_sign_latency_ms`. Tous les autres qu'une sonde rapporte sont du
     * temps mural, qui ne se compare à rien. Confondre les deux a déjà coûté
     * une conclusion erronée côté iOS, corrigée le 2026-08-15.
     */
    val signLatencyMs: Long,
)

/**
 * Scellement d'octets **remis** — le second point d'entrée du cœur, à côté de
 * l'acquisition (spec §2.5, « contenu acquis, contenu fourni »).
 *
 * Un intégrateur qui possède déjà son écran photo passe par ici. Ce n'est pas
 * un mode dégradé mais une preuve **plus étroite** : ni position, ni
 * dimensions, ni plafond de recapture, parce que le cœur n'a pas observé
 * l'acquisition et n'affirme donc rien du monde physique. L'enveloppe dit
 * exactement ce qu'elle sait — *cet appareil, dans cet état, a signé ces
 * octets-là à cet instant, sous une clé matérielle attestée*.
 *
 * Le profil produit est toujours `core`. Le nonce doit avoir été émis pour ce
 * profil : le serveur rejette une enveloppe dont le profil signé diffère de
 * celui du nonce, et il a raison de le faire — sans ce contrôle, un client
 * compromis déclarerait `core` pour une acquisition et échapperait au plafond.
 *
 * Aucune décision de validité n'est prise ici (invariant 1) : le cœur
 * collecte, assemble, signe, et le serveur juge.
 *
 * Toutes les méthodes sont **bloquantes** — Keystore et Play Integrity le
 * sont — et ne doivent jamais être appelées sur le fil principal.
 */
class Sealer(
    private val context: Context,
    private val deployment: String,
    private val keyAlias: String,
    private val appVersion: String,
    private val freshness: FreshnessSource,
) {

    /**
     * Scelle [content] sous le nonce du serveur et rend l'enveloppe encodée.
     *
     * [acquiredAtElapsedMs] est l'instant d'origine sur l'horloge monotone,
     * qui sert à mesurer `media[6]`. Il vaut par défaut l'entrée dans cette
     * méthode — ce qui est la seule chose honnête pour des octets remis, dont
     * le cœur ignore l'âge. L'acquisition (A4.2) passera l'instant de
     * l'obturateur, et c'est là seulement que le champ discrimine une
     * injection.
     *
     * [prevDigest] chaîne l'enveloppe à la précédente (spec §9). Facultatif.
     */
    fun seal(
        content: ByteArray,
        mimeType: String,
        nonce: ByteArray,
        acquiredAtElapsedMs: Long = SystemClock.elapsedRealtime(),
        prevDigest: ByteArray? = null,
    ): SealedEnvelope {
        val mediaDigest = sha256(content)
        val timing = DeviceState.timing(context)
        val posture = DeviceState.posture(context, appVersion)

        // `media[6]` s'arrête à l'encodage de la charge utile, et pas à la
        // signature : le champ est *dans* ce qui est encodé, donc il ne peut
        // pas mesurer ce qui vient après lui. Ce qui reste dehors est le
        // jeton de fraîcheur et la signature — mesurés à 36–39 ms et
        // quelques millisecondes sur SM-X200, donc une constante, là où le
        // discriminant recherché est le temps passé *avant*.
        val latencyMs = SystemClock.elapsedRealtime() - acquiredAtElapsedMs
        require(latencyMs >= 0) { "instant d'acquisition postérieur au scellement" }

        val payload = CorePayload.build(
            nonce = nonce,
            media = Media(
                digest = mediaDigest,
                mimeType = mimeType,
                sizeBytes = content.size.toLong(),
                signLatencyMs = latencyMs,
            ),
            timing = timing,
            posture = posture,
            prevDigest = prevDigest,
        )
        return finir(payload, CorePayload.PROFILE, nonce, mediaDigest, latencyMs)
    }

    /**
     * Scelle une image **acquise par le cœur**, avec ses mesures — profil
     * `capture`.
     *
     * Séparé de l'acquisition elle-même pour qu'une sonde puisse rapporter
     * chaque étape sans réimplémenter l'assemblage. **Et non pour offrir un
     * chemin où un appelant fournirait ses propres octets en profil
     * `capture`** : ce chemin-là est [seal] avec un contenu remis, et il
     * produit `core`. La distinction est tout le sujet d'ADR-0008 — le profil
     * n'affirme que ce que le cœur a observé.
     *
     * [position] est obligatoire, le profil l'exige. [claims] peut être vide,
     * mais une position sans corroboration se fait dégrader : le vérificateur
     * n'a alors rien pour la confronter.
     */
    fun seal(
        image: CapturedImage,
        position: Position,
        claims: List<Claim>,
        nonce: ByteArray,
        prevDigest: ByteArray? = null,
    ): SealedEnvelope {
        val mediaDigest = sha256(image.bytes)
        val timing = DeviceState.timing(context)
        val posture = DeviceState.posture(context, appVersion)

        // **L'origine est l'obturateur, pas l'entrée dans cette méthode.**
        // C'est là seulement que `media[6]` discrimine une injection, en
        // mesurant le temps réellement passé entre capteur et charge utile.
        // Compter depuis l'entrée ici mesurerait le scellement, qui ne prouve
        // rien : il est rapide même quand les octets viennent d'ailleurs.
        val latencyMs = SystemClock.elapsedRealtime() - image.shutterElapsedMs
        require(latencyMs >= 0) { "obturateur postérieur au scellement" }

        val payload = CapturePayload.build(
            nonce = nonce,
            media = Media(
                digest = mediaDigest,
                // Le type vient du format réellement encodé, jamais d'un
                // littéral posé ici : deux sources se seraient contredites en
                // silence, et l'enveloppe aurait porté un type faux mais signé
                // (ADR-0007 point 3).
                mimeType = image.format.mimeType,
                sizeBytes = image.bytes.size.toLong(),
                signLatencyMs = latencyMs,
                pixelWidth = image.pixelWidth,
                pixelHeight = image.pixelHeight,
            ),
            position = position,
            timing = timing,
            posture = posture,
            claims = claims,
            prevDigest = prevDigest,
        )
        return finir(payload, CapturePayload.PROFILE, nonce, mediaDigest, latencyMs)
    }

    /**
     * Encodage, règle R1, jeton et signature — communs aux deux profils.
     *
     * **R1 ne vit qu'ici**, et c'est délibéré : deux copies du calcul du défi
     * finiraient par diverger, et l'invariant 2 ne se rattrape pas d'un côté
     * quand l'autre a glissé.
     */
    private fun finir(
        payload: Map<Int, Any>,
        profile: String,
        nonce: ByteArray,
        mediaDigest: ByteArray,
        latencyMs: Long,
    ): SealedEnvelope {
        val payloadBytes = Cbor.encode(payload)

        // Règle R1, non négociable : le défi vaut exactement
        // SHA-256(payload_bytes ‖ nonce), sur les octets encodés et jamais
        // sur un réencodage de la structure.
        val challenge = sha256(payloadBytes + nonce)
        val token = freshness.token(challenge)

        val protectedBytes =
            Cose.protectedHeader(KeystoreKeys.kid(keyAlias), deployment, profile)
        val signature =
            KeystoreKeys.signRaw(keyAlias, Cose.sigStructure(protectedBytes, payloadBytes))

        return SealedEnvelope(
            bytes = Cose.envelope(
                protectedBytes,
                mapOf(1 to freshness.kind, 2 to token),
                payloadBytes,
                signature,
            ),
            payloadBytes = payloadBytes,
            challenge = challenge,
            mediaDigest = mediaDigest,
            signLatencyMs = latencyMs,
        )
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}
