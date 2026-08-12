package org.probative.core.payload

import com.google.gson.JsonParser
import org.probative.core.cbor.Cbor
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Le vecteur `core` reproduit **par le code qui tourne sur l'appareil**.
 *
 * Distinct de `GoldenVectorsTest`, et la nuance est tout l'intérêt : là-bas,
 * la charge utile est bâtie à la main dans le test, ce qui éprouve
 * l'encodeur CBOR. Ici, elle passe par [CorePayload.build], celui-là même
 * qu'appelle `Sealer` — un décalage entre la structure produite sur appareil
 * et `factory.make_payload` échouerait donc sur l'hôte, avant d'aller
 * chercher une SM-X200 et de lire un `SIGNATURE_INVALID` sans cause visible.
 *
 * Seule la collecte reste hors de portée d'un test d'hôte : les valeurs sont
 * ici celles du vecteur, comme si l'appareil les avait mesurées.
 */
class CorePayloadVectorTest {

    private val dir = File(
        requireNotNull(System.getProperty("probative.vectors.dir")) {
            "propriété probative.vectors.dir absente : lancer via Gradle"
        }
    )
    private val inputs =
        JsonParser.parseString(File(dir, "manifest.json").readText())
            .asJsonObject.getAsJsonObject("core")

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `charge utile du noyau octet a octet`() {
        val payload = CorePayload.build(
            nonce = hex(inputs["nonce_hex"].asString),
            media = Media(
                digest = hex(inputs["media_digest_hex"].asString),
                mimeType = "application/pdf",
                sizeBytes = 1_842_301,
                signLatencyMs = 85,
            ),
            timing = Timing(
                wallMs = inputs["wall_ms"].asLong,
                elapsedRealtimeMs = 4_312_004,
                utcOffsetMinutes = 120,
                automaticTime = true,
            ),
            posture = Posture(
                platform = "android",
                osVersion = "14",
                appVersion = "0.1.0",
                debuggerAttached = false,
                emulatorSuspected = false,
                developerMode = false,
                mockLocation = false,
                suspiciousPackages = emptyList(),
            ),
            prevDigest = hex(inputs["prev_digest_hex"].asString),
        )

        assertArrayEquals(
            File(dir, "core.payload.cbor").readBytes(),
            Cbor.encode(payload),
        )
    }

    /**
     * Une mesure non faite s'omet, elle ne se simule pas. C'est ce que rend
     * `DeviceState` pour la position simulée et les paquets suspects, et le
     * serveur doit voir la différence entre « rien détecté » et « rien
     * cherché ».
     */
    @Test
    fun `les champs optionnels absents ne sont pas encodes`() {
        val posture = Posture(
            platform = "android",
            osVersion = "14",
            appVersion = "0.1.0",
            debuggerAttached = false,
            emulatorSuspected = false,
        ).toCbor()

        assertArrayEquals(intArrayOf(1, 2, 3, 4, 5), posture.keys.sorted().toIntArray())
    }
}
