package dev.attestedcapture.core.keys

import com.google.gson.JsonParser
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * La convention `kid` doit être identique sur les trois implémentations.
 * Le manifest des vecteurs d'or fournit un couple (clé publique X9.62,
 * kid) de référence : l'encodage doit le reproduire au retour exact.
 */
class EcPublicKeysTest {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun p256(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)

    private fun publicKeyFromX962(encoded: ByteArray): ECPublicKey {
        require(encoded.size == 65 && encoded[0] == 4.toByte())
        val x = BigInteger(1, encoded.copyOfRange(1, 33))
        val y = BigInteger(1, encoded.copyOfRange(33, 65))
        return KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(x, y), p256())) as ECPublicKey
    }

    @Test
    fun `aller-retour exact sur les cles du manifest`() {
        val dir = File(System.getProperty("ac.vectors.dir")!!)
        val manifest = JsonParser.parseString(File(dir, "manifest.json").readText()).asJsonObject
        for (platform in listOf("android", "ios")) {
            val inputs = manifest.getAsJsonObject(platform)
            val x962 = hex(inputs["public_key_x962_hex"].asString)
            val key = publicKeyFromX962(x962)

            assertArrayEquals(platform, x962, EcPublicKeys.x962Uncompressed(key))
            assertArrayEquals(platform, hex(inputs["kid_hex"].asString), EcPublicKeys.kid(key))
        }
    }

    @Test
    fun `cadrage des coordonnees courtes`() {
        // Une coordonnée sur 256 commence par un octet nul : la boucle
        // cherche jusqu'à en tenir une (64 clés attendues, borne large —
        // la probabilité d'échec est de l'ordre de 1e-7), et vérifie que
        // le cadrage à 32 octets la restitue exactement.
        val generator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        var shortSeen = false
        for (attempt in 1..2_000) {
            val key = generator.generateKeyPair().public as ECPublicKey
            val encoded = EcPublicKeys.x962Uncompressed(key)
            assertEquals(65, encoded.size)
            assertEquals(4.toByte(), encoded[0])
            // L'aller-retour par le point doit être exact.
            assertArrayEquals(encoded, EcPublicKeys.x962Uncompressed(publicKeyFromX962(encoded)))
            if (encoded[1] == 0.toByte() || encoded[33] == 0.toByte()) {
                shortSeen = true
                break
            }
        }
        assertTrue("aucune coordonnée courte rencontrée : cas non exercé", shortSeen)
    }
}
