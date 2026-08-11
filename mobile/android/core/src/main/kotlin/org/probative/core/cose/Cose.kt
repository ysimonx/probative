package org.probative.core.cose

import org.probative.core.cbor.Cbor
import org.probative.core.cbor.CborTag

/**
 * Assemblage `COSE_Sign1` du format `probative/0.1` (spec §2, ADR-0001).
 *
 * Uniquement de la construction d'octets : aucune décision, aucun accès
 * au Keystore ici. La signature est fournie par l'appelant — c'est ce qui
 * rend chaque étape comparable aux vecteurs d'or du vérificateur.
 */
object Cose {

    private const val SPEC = "probative/0.1"

    /**
     * En-tête protégé encodé : alg ES256, kid, version de spec, déploiement,
     * profil.
     *
     * Le profil (label 102, spec §2.5, ADR-0005) est ici et non dans la
     * charge utile : le retirer ou le changer invalide la signature. Sa
     * valeur est celle rendue par la route `/nonce` du serveur — la
     * déclarer de son propre chef fait rejeter l'enveloppe.
     */
    fun protectedHeader(kid: ByteArray, deployment: String, profile: String): ByteArray =
        Cbor.encode(
            mapOf(
                1 to -7,
                4 to kid,
                100 to SPEC,
                101 to deployment,
                102 to profile,
            )
        )

    /**
     * `Sig_structure` (RFC 8152 §4.4) — les octets réellement signés.
     * Contexte "Signature1", `external_aad` vide, en-tête protégé et
     * charge utile en chaînes d'octets, jamais re-décodés.
     */
    fun sigStructure(protectedBytes: ByteArray, payloadBytes: ByteArray): ByteArray =
        Cbor.encode(listOf("Signature1", protectedBytes, ByteArray(0), payloadBytes))

    /**
     * Enveloppe complète : `COSE_Sign1` étiqueté (tag 18). L'en-tête non
     * protégé ne contient que la preuve de fraîcheur (label 200), qui se
     * lie au contenu par la règle R1 — pas par la signature.
     */
    fun envelope(
        protectedBytes: ByteArray,
        freshness: Map<Int, Any>,
        payloadBytes: ByteArray,
        signature: ByteArray,
    ): ByteArray {
        require(signature.size == 64) { "signature r‖s de 64 octets attendue" }
        return Cbor.encode(
            CborTag(
                18,
                listOf(protectedBytes, mapOf(200 to freshness), payloadBytes, signature),
            )
        )
    }

    /**
     * Convertit une signature ECDSA DER — ce que rend le Keystore — vers la
     * forme brute `r‖s` de COSE : deux entiers non signés cadrés à 32 octets.
     */
    fun rawSignatureFromDer(der: ByteArray): ByteArray {
        val reader = DerReader(der)
        reader.expect(0x30)
        reader.readLength()
        val r = reader.readInteger()
        val s = reader.readInteger()
        require(reader.exhausted()) { "octets résiduels après la séquence DER" }
        return leftPad(r) + leftPad(s)
    }

    private fun leftPad(unsigned: ByteArray): ByteArray {
        require(unsigned.size <= 32) { "entier de plus de 32 octets : pas du P-256" }
        return ByteArray(32 - unsigned.size) + unsigned
    }

    /** Lecteur DER minimal : juste ce qu'exige ECDSA-Sig-Value. */
    private class DerReader(private val data: ByteArray) {
        private var pos = 0

        fun expect(tag: Int) {
            require(pos < data.size && (data[pos].toInt() and 0xFF) == tag) {
                "octet DER $tag attendu à la position $pos"
            }
            pos++
        }

        fun readLength(): Int {
            require(pos < data.size) { "longueur DER tronquée" }
            val first = data[pos++].toInt() and 0xFF
            if (first < 0x80) return first
            val count = first and 0x7F
            // Une signature P-256 tient toujours sur une longueur d'un octet.
            require(count == 1) { "longueur DER inattendue pour du P-256" }
            require(pos < data.size) { "longueur DER tronquée" }
            return data[pos++].toInt() and 0xFF
        }

        fun readInteger(): ByteArray {
            expect(0x02)
            val length = readLength()
            require(length in 1..33 && pos + length <= data.size) {
                "entier DER de taille invalide : $length"
            }
            var start = pos
            var remaining = length
            // Le zéro de tête n'existe que pour neutraliser un bit de signe.
            while (remaining > 1 && data[start].toInt() == 0) {
                start++
                remaining--
            }
            val value = data.copyOfRange(start, start + remaining)
            pos += length
            return value
        }

        fun exhausted(): Boolean = pos == data.size
    }
}
