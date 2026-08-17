package org.probative.core.payload

import com.google.gson.JsonParser
import org.probative.core.cbor.Cbor
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Le vecteur `android` — profil **`capture`** — reproduit par le code qui
 * tourne sur l'appareil.
 *
 * Pendant de `CorePayloadVectorTest`, et la même nuance en fait tout
 * l'intérêt : `GoldenVectorsTest` bâtit sa charge utile à la main et n'éprouve
 * donc que l'encodeur CBOR. Ici elle passe par [CapturePayload.build],
 * celui-là même qu'appelle `Sealer.seal(image = …)`.
 *
 * Sans ce test, `CapturePayload` ne serait que plausible : il compile, il a
 * l'air juste, et un décalage d'un label ou d'un type ne se verrait qu'après
 * une capture réelle sur SM-X200, sous la forme d'un rejet serveur sans cause
 * lisible. L'implémentation de référence reste `factory.make_payload` — si ce
 * code produit autre chose, c'est ce code qui s'écarte.
 *
 * Seule la collecte reste hors de portée d'un test d'hôte : les valeurs sont
 * celles du vecteur, comme si l'appareil les avait mesurées.
 */
class CapturePayloadVectorTest {

    private val dir = File(
        requireNotNull(System.getProperty("probative.vectors.dir")) {
            "propriété probative.vectors.dir absente : lancer via Gradle"
        }
    )
    private val inputs =
        JsonParser.parseString(File(dir, "manifest.json").readText())
            .asJsonObject.getAsJsonObject("android")

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `charge utile d'acquisition octet a octet`() {
        val prev = inputs["prev_digest_hex"]

        val payload = CapturePayload.build(
            nonce = hex(inputs["nonce_hex"].asString),
            media = Media(
                digest = hex(inputs["media_digest_hex"].asString),
                mimeType = "image/jpeg",
                sizeBytes = 1_842_301,
                signLatencyMs = 85,
                pixelWidth = 4_032,
                pixelHeight = 3_024,
            ),
            position = Position(
                latitude = 48.2973,
                longitude = 4.0744,
                horizontalAccuracy = 8.0,
                provider = Position.Provider.GNSS,
                fixAgeMs = 1_200,
                altitude = 112.0,
                verticalAccuracy = 4.0,
                // Exposé par Android, absent d'iOS : c'est ce label qui rend
                // ce vecteur différent d'`ios` au-delà de la posture.
                satellites = 11,
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
            claims = listOf(
                Claim("baro-alt", "barometer", 4_210, 115.0),
                Claim("baro", "barometer", 4_210, 999.4),
                Claim(
                    "motion",
                    "accelerometer",
                    4_100,
                    listOf(
                        listOf(0, 0.01, 0.02, 9.79),
                        listOf(500, 0.03, 0.01, 9.81),
                    ),
                ),
                Claim("steps", "pedometer", 4_180, 0),
            ),
            prevDigest = if (prev.isJsonNull) null else hex(prev.asString),
        )

        assertArrayEquals(
            File(dir, "android.payload.cbor").readBytes(),
            Cbor.encode(payload),
        )
    }
}
