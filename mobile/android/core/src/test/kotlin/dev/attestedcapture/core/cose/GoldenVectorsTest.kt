package dev.attestedcapture.core.cose

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.attestedcapture.core.cbor.Cbor
import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Le contrat du spike : reproduire octet à octet les vecteurs d'or du
 * vérificateur (`verifier-python/tests/vectors/`, source unique — le
 * chemin arrive par la propriété système `ac.vectors.dir`).
 *
 * La construction de la charge utile reflète `factory.make_payload`, qui
 * est l'implémentation de référence : si ce test ne peut pas reproduire
 * un vecteur, c'est ce code-ci qui s'écarte de la spécification.
 */
class GoldenVectorsTest {

    private val dir = File(
        requireNotNull(System.getProperty("ac.vectors.dir")) {
            "propriété ac.vectors.dir absente : lancer via Gradle"
        }
    )
    private val manifest =
        JsonParser.parseString(File(dir, "manifest.json").readText()).asJsonObject

    private fun vector(name: String): ByteArray = File(dir, name).readBytes()

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun inputs(platform: String): JsonObject = manifest.getAsJsonObject(platform)

    /** Miroir de `factory.make_payload`, valeurs par défaut comprises. */
    private fun payloadFor(platform: String): Map<Int, Any> {
        val inputs = inputs(platform)

        val position = mutableMapOf<Int, Any>(
            1 to 48.2973,
            2 to 4.0744,
            3 to 8.0,
            4 to 112.0,
            5 to 4.0,
            6 to "gnss",
            7 to 1_200,
        )
        val posture = mutableMapOf<Int, Any>(
            1 to platform,
            2 to if (platform == "android") "14" else "17.4",
            3 to "0.1.0",
            4 to false,
            5 to false,
        )
        if (platform == "android") {
            position[8] = 11
            posture[6] = false
            posture[7] = false
            posture[8] = emptyList<String>()
        } else {
            posture[9] = false
        }

        val claims = listOf(
            mapOf(1 to "baro-alt", 2 to "barometer", 3 to 4_210, 4 to 115.0),
            mapOf(1 to "baro", 2 to "barometer", 3 to 4_210, 4 to 999.4),
            mapOf(
                1 to "motion",
                2 to "accelerometer",
                3 to 4_100,
                4 to listOf(listOf(0, 0.01, 0.02, 9.79), listOf(500, 0.03, 0.01, 9.81)),
            ),
            mapOf(1 to "steps", 2 to "pedometer", 3 to 4_180, 4 to 0),
        )

        val payload = mutableMapOf<Int, Any>(
            1 to hex(inputs["nonce_hex"].asString),
            2 to mapOf(
                1 to "sha-256",
                2 to hex(inputs["media_digest_hex"].asString),
                3 to "image/jpeg",
                4 to 1_842_301,
                5 to listOf(4_032, 3_024),
                6 to 85,
            ),
            3 to position,
            4 to mapOf(1 to inputs["wall_ms"].asLong, 2 to 4_312_004, 3 to 120, 4 to true),
            5 to posture,
            6 to claims,
        )
        if (!inputs["prev_digest_hex"].isJsonNull) {
            payload[7] = hex(inputs["prev_digest_hex"].asString)
        }
        return payload
    }

    @Test
    fun `charge utile octet a octet`() {
        for (platform in listOf("android", "ios")) {
            assertArrayEquals(
                platform,
                vector("$platform.payload.cbor"),
                Cbor.encode(payloadFor(platform)),
            )
        }
    }

    @Test
    fun `en-tete protege octet a octet`() {
        for (platform in listOf("android", "ios")) {
            assertArrayEquals(
                platform,
                vector("$platform.protected.cbor"),
                Cose.protectedHeader(hex(inputs(platform)["kid_hex"].asString), "test-deployment"),
            )
        }
    }

    @Test
    fun `sig_structure octet a octet`() {
        for (platform in listOf("android", "ios")) {
            assertArrayEquals(
                platform,
                vector("$platform.sig_structure.cbor"),
                Cose.sigStructure(
                    vector("$platform.protected.cbor"),
                    vector("$platform.payload.cbor"),
                ),
            )
        }
    }

    @Test
    fun `defi R1 sur les octets encodes`() {
        for (platform in listOf("android", "ios")) {
            val challenge = sha256(
                vector("$platform.payload.cbor") + hex(inputs(platform)["nonce_hex"].asString)
            )
            assertArrayEquals(platform, vector("$platform.challenge.bin"), challenge)
        }
    }

    @Test
    fun `assemblage d'enveloppe octet a octet`() {
        // La signature des vecteurs est ECDSA déterministe, irréproductible
        // avec une clé matérielle : on la prélève de l'enveloppe (les 64
        // derniers octets) et on vérifie que tout le reste s'assemble à
        // l'identique autour d'elle.
        for (platform in listOf("android", "ios")) {
            val inputs = inputs(platform)
            val envelope = vector("$platform.envelope.acap")
            val signature = envelope.copyOfRange(envelope.size - 64, envelope.size)

            val token = "NULLTOKEN:".toByteArray(Charsets.US_ASCII) +
                vector("$platform.challenge.bin")
            val freshness = mutableMapOf<Int, Any>(
                1 to inputs["freshness_kind"].asString,
                2 to token,
            )
            if (!inputs["assertion_counter"].isJsonNull) {
                freshness[3] = inputs["assertion_counter"].asInt
            }

            assertArrayEquals(
                platform,
                envelope,
                Cose.envelope(
                    vector("$platform.protected.cbor"),
                    freshness,
                    vector("$platform.payload.cbor"),
                    signature,
                ),
            )
        }
    }
}
