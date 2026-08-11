package org.probative.core.keys

import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

/**
 * Encodage X9.62 non compressé et identifiant de clé du format `probative/0.1`.
 *
 * Le `kid` vaut SHA-256 de la clé publique en point non compressé
 * (`04 ‖ X ‖ Y`, 65 octets) : même convention que la fabrique de
 * référence (`factory.kid_for`) et que le cœur iOS. C'est lui qui, dans
 * l'en-tête protégé, lie la signature à la clé enrôlée (règle R2).
 */
object EcPublicKeys {

    fun x962Uncompressed(key: ECPublicKey): ByteArray =
        byteArrayOf(0x04) + coordinate(key.w.affineX.toByteArray()) +
            coordinate(key.w.affineY.toByteArray())

    fun kid(key: ECPublicKey): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(x962Uncompressed(key))

    /**
     * Cadre une coordonnée à 32 octets. `BigInteger.toByteArray` rend un
     * complément à deux minimal : un octet de signe peut précéder, des
     * zéros de tête peuvent manquer.
     */
    private fun coordinate(raw: ByteArray): ByteArray {
        val trimmed = raw.dropWhile { it == 0.toByte() }.toByteArray()
        require(trimmed.size <= 32) { "coordonnée de plus de 32 octets : pas du P-256" }
        return ByteArray(32 - trimmed.size) + trimmed
    }
}
