package org.probative.core.cose

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Conversion DER → `r‖s`. Le Keystore rend du DER ; COSE exige la forme
 * brute. La validation croise deux fournisseurs JCA : la signature DER
 * convertie doit se vérifier sous `SHA256withECDSAinP1363Format`.
 */
class DerSignatureTest {

    @Test
    fun `conversion validee par le fournisseur P1363`() {
        val generator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val keys = generator.generateKeyPair()
        val message = "octets a signer".toByteArray()

        // Plusieurs signatures : r et s changent de taille DER selon leurs
        // zéros de tête, c'est précisément ce que la conversion doit absorber.
        repeat(32) {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(keys.private)
                update(message)
                sign()
            }
            val raw = Cose.rawSignatureFromDer(der)
            assertEquals(64, raw.size)

            val valid = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initVerify(keys.public)
                update(message)
                verify(raw)
            }
            assertTrue("signature convertie refusée", valid)
        }
    }

    @Test
    fun `cadrage des petits entiers et des zeros de tete`() {
        // r = 1 (1 octet), s = valeur à bit de poids fort levé, précédée du
        // zéro DER qui neutralise le bit de signe.
        val s = ByteArray(32) { 0xAB.toByte() }.also { it[0] = 0x80.toByte() }
        val der = byteArrayOf(0x30, 38, 0x02, 1, 1, 0x02, 33, 0) + s

        val raw = Cose.rawSignatureFromDer(der)

        val expectedR = ByteArray(32).also { it[31] = 1 }
        assertArrayEquals(expectedR, raw.copyOfRange(0, 32))
        assertArrayEquals(s, raw.copyOfRange(32, 64))
    }
}
