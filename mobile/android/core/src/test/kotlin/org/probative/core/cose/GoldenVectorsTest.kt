package org.probative.core.cose

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.probative.core.cbor.Cbor
import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Le contrat du spike : reproduire octet à octet les vecteurs d'or du
 * vérificateur (`verifier-python/tests/vectors/`, source unique — le
 * chemin arrive par la propriété système `probative.vectors.dir`).
 *
 * La construction de la charge utile reflète `factory.make_payload`, qui
 * est l'implémentation de référence : si ce test ne peut pas reproduire
 * un vecteur, c'est ce code-ci qui s'écarte de la spécification.
 */
class GoldenVectorsTest {

    private companion object {
        /**
         * Les trois jeux de vecteurs. `core` n'est pas décoratif : c'est la
         * seule forme sans position ni dimensions, et donc la seule qui
         * vérifie que l'encodeur ne suppose pas une acquisition (ADR-0005).
         */
        val VECTOR_SETS = listOf("android", "ios", "core")
    }

    private val dir = File(
        requireNotNull(System.getProperty("probative.vectors.dir")) {
            "propriété probative.vectors.dir absente : lancer via Gradle"
        }
    )
    private val manifest =
        JsonParser.parseString(File(dir, "manifest.json").readText()).asJsonObject

    private fun vector(name: String): ByteArray = File(dir, name).readBytes()

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun inputs(name: String): JsonObject = manifest.getAsJsonObject(name)

    private fun platformOf(name: String): String = inputs(name)["platform"].asString

    private fun profileOf(name: String): String = inputs(name)["profile"].asString

    /** Miroir de `factory.make_payload`, valeurs par défaut comprises. */
    private fun payloadFor(name: String): Map<Int, Any> {
        val inputs = inputs(name)
        val platform = platformOf(name)
        val capture = profileOf(name) == "capture"

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

        val media = mutableMapOf<Int, Any>(
            1 to "sha-256",
            2 to hex(inputs["media_digest_hex"].asString),
            3 to if (capture) "image/jpeg" else "application/pdf",
            4 to 1_842_301,
            6 to 85,
        )
        val payload = mutableMapOf<Int, Any>(
            1 to hex(inputs["nonce_hex"].asString),
            2 to media,
            4 to mapOf(1 to inputs["wall_ms"].asLong, 2 to 4_312_004, 3 to 120, 4 to true),
            5 to posture,
        )

        // Le noyau ne décrit que des octets : ni dimensions, ni position,
        // ni corroboration — rien qui suppose un capteur ou un lieu.
        if (capture) {
            media[5] = listOf(4_032, 3_024)
            payload[3] = position
            payload[6] = claims
        }

        if (!inputs["prev_digest_hex"].isJsonNull) {
            payload[7] = hex(inputs["prev_digest_hex"].asString)
        }
        return payload
    }

    @Test
    fun `charge utile octet a octet`() {
        for (name in VECTOR_SETS) {
            assertArrayEquals(
                name,
                vector("$name.payload.cbor"),
                Cbor.encode(payloadFor(name)),
            )
        }
    }

    @Test
    fun `en-tete protege octet a octet`() {
        for (name in VECTOR_SETS) {
            assertArrayEquals(
                name,
                vector("$name.protected.cbor"),
                Cose.protectedHeader(
                    hex(inputs(name)["kid_hex"].asString),
                    "test-deployment",
                    profileOf(name),
                ),
            )
        }
    }

    @Test
    fun `sig_structure octet a octet`() {
        for (name in VECTOR_SETS) {
            assertArrayEquals(
                name,
                vector("$name.sig_structure.cbor"),
                Cose.sigStructure(
                    vector("$name.protected.cbor"),
                    vector("$name.payload.cbor"),
                ),
            )
        }
    }

    @Test
    fun `defi R1 sur les octets encodes`() {
        for (name in VECTOR_SETS) {
            val challenge = sha256(
                vector("$name.payload.cbor") + hex(inputs(name)["nonce_hex"].asString)
            )
            assertArrayEquals(name, vector("$name.challenge.bin"), challenge)
        }
    }

    @Test
    fun `assemblage d'enveloppe octet a octet`() {
        // La signature des vecteurs est ECDSA déterministe, irréproductible
        // avec une clé matérielle : on la prélève de l'enveloppe (les 64
        // derniers octets) et on vérifie que tout le reste s'assemble à
        // l'identique autour d'elle.
        for (name in VECTOR_SETS) {
            val inputs = inputs(name)
            val envelope = vector("$name.envelope.prbv")
            val signature = envelope.copyOfRange(envelope.size - 64, envelope.size)

            val token = "NULLTOKEN:".toByteArray(Charsets.US_ASCII) +
                vector("$name.challenge.bin")
            val freshness = mutableMapOf<Int, Any>(
                1 to inputs["freshness_kind"].asString,
                2 to token,
            )
            if (!inputs["assertion_counter"].isJsonNull) {
                freshness[3] = inputs["assertion_counter"].asInt
            }

            assertArrayEquals(
                name,
                envelope,
                Cose.envelope(
                    vector("$name.protected.cbor"),
                    freshness,
                    vector("$name.payload.cbor"),
                    signature,
                ),
            )
        }
    }
}
