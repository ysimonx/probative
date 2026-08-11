package org.probative.core.cbor

import java.io.ByteArrayOutputStream

/**
 * Valeur CBOR étiquetée (RFC 8949 §3.4) — l'enveloppe complète porte le tag 18.
 */
data class CborTag(val tag: Long, val value: Any)

/**
 * Encodeur CBOR canonique, strict nécessaire du format `probative/0.1`.
 *
 * Pas de bibliothèque généraliste, pour la même raison que côté serveur
 * (ADR-0001) : la surface acceptée doit rester minimale, et la canonicité
 * doit être garantie octet à octet — elle est validée contre les vecteurs
 * d'or du vérificateur, qui font foi. Deux implémentations doivent
 * produire des octets identiques pour une même charge utile, sinon la
 * signature ne se vérifie pas (spec §7).
 *
 * Types acceptés : Int/Long, Boolean, String, ByteArray, List, Map à clés
 * entières, Double, [CborTag]. Tout le reste est rejeté bruyamment : un
 * type inattendu est un bogue d'appelant, jamais une valeur à deviner.
 */
object Cbor {

    fun encode(value: Any): ByteArray {
        val out = ByteArrayOutputStream()
        write(out, value)
        return out.toByteArray()
    }

    private fun write(out: ByteArrayOutputStream, value: Any) {
        when (value) {
            is Int -> writeInteger(out, value.toLong())
            is Long -> writeInteger(out, value)
            is Boolean -> out.write(if (value) 0xF5 else 0xF4)
            is String -> {
                val utf8 = value.toByteArray(Charsets.UTF_8)
                writeHead(out, MAJOR_TEXT, utf8.size.toLong())
                out.write(utf8)
            }
            is ByteArray -> {
                writeHead(out, MAJOR_BYTES, value.size.toLong())
                out.write(value)
            }
            is List<*> -> {
                writeHead(out, MAJOR_ARRAY, value.size.toLong())
                for (item in value) write(out, requireNotNull(item) { "null dans un tableau" })
            }
            is Map<*, *> -> writeMap(out, value)
            is Double -> writeFloat(out, value)
            is CborTag -> {
                writeHead(out, MAJOR_TAG, value.tag)
                write(out, value.value)
            }
            // Float est refusé : 0.01f élargi en Double ne vaut pas 0.01,
            // et l'appelant ne s'en apercevrait qu'à la vérification de
            // signature. Les mesures se manipulent en Double, point.
            else -> throw IllegalArgumentException(
                "type non encodable : ${value::class.qualifiedName}"
            )
        }
    }

    private fun writeInteger(out: ByteArrayOutputStream, n: Long) {
        if (n >= 0) writeHead(out, MAJOR_UINT, n) else writeHead(out, MAJOR_NINT, -1L - n)
    }

    /** Tête majeure + argument en forme la plus courte (RFC 8949 §4.2.1). */
    private fun writeHead(out: ByteArrayOutputStream, major: Int, argument: Long) {
        require(argument >= 0) { "argument négatif" }
        val m = major shl 5
        when {
            argument < 24 -> out.write(m or argument.toInt())
            argument <= 0xFF -> {
                out.write(m or 24)
                out.write(argument.toInt())
            }
            argument <= 0xFFFF -> {
                out.write(m or 25)
                out.write((argument ushr 8).toInt())
                out.write((argument and 0xFF).toInt())
            }
            argument <= 0xFFFFFFFFL -> {
                out.write(m or 26)
                for (shift in 24 downTo 0 step 8) out.write(((argument ushr shift) and 0xFF).toInt())
            }
            else -> {
                out.write(m or 27)
                for (shift in 56 downTo 0 step 8) out.write(((argument ushr shift) and 0xFF).toInt())
            }
        }
    }

    private fun writeMap(out: ByteArrayOutputStream, map: Map<*, *>) {
        // Tri par octets d'encodage croissants (RFC 8949 §4.2.1). Le format
        // n'a que des clés entières positives : l'ordre coïncide alors avec
        // l'ordre numérique — et avec le tri « longueur d'abord » de cbor2,
        // l'implémentation de référence. C'est l'encodage qui fait foi.
        val entries = map.entries.map { (k, v) ->
            require(k is Int || k is Long) { "clé de map non entière : $k" }
            val key = encode(k)
            key to encode(requireNotNull(v) { "null pour la clé $k" })
        }
        writeHead(out, MAJOR_MAP, entries.size.toLong())
        for ((key, encoded) in entries.sortedWith { a, b -> compareBytes(a.first, b.first) }) {
            out.write(key)
            out.write(encoded)
        }
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }

    // --- flottants : forme la plus courte qui préserve la valeur ---------
    //
    // Les trois largeurs coexistent dans une même charge utile (8.0 tient
    // en demi-précision, 48.2973 exige du float64). Émettre du float64
    // partout produirait des octets différents des vecteurs d'or — donc
    // une signature invalide côté serveur.

    private fun writeFloat(out: ByteArrayOutputStream, d: Double) {
        if (d.isNaN()) {
            // NaN canonique unique : le format ne transporte aucun NaN,
            // mais l'encodeur ne doit pas pouvoir en produire deux formes.
            out.write(byteArrayOf(0xF9.toByte(), 0x7E, 0x00))
            return
        }
        val half = halfBitsOrNull(d)
        if (half != null) {
            out.write(0xF9)
            out.write(half ushr 8)
            out.write(half and 0xFF)
            return
        }
        val f = d.toFloat()
        if (f.toDouble() == d) {
            out.write(0xFA)
            val bits = java.lang.Float.floatToIntBits(f)
            for (shift in 24 downTo 0 step 8) out.write((bits ushr shift) and 0xFF)
            return
        }
        out.write(0xFB)
        val bits = java.lang.Double.doubleToLongBits(d)
        for (shift in 56 downTo 0 step 8) out.write(((bits ushr shift) and 0xFF).toInt())
    }

    /** Bits IEEE 754 demi-précision si la valeur y est exacte, sinon null. */
    private fun halfBitsOrNull(d: Double): Int? {
        val f = d.toFloat()
        if (f.toDouble() != d) return null
        val bits = java.lang.Float.floatToIntBits(f)
        val sign = (bits ushr 16) and 0x8000
        val exp32 = (bits ushr 23) and 0xFF
        val mant32 = bits and 0x7F_FFFF

        if (exp32 == 0xFF) {
            // ±Infini tient en demi-précision ; NaN est traité en amont.
            return sign or 0x7C00
        }
        if (exp32 == 0) {
            // ±0.0 exact ; les sous-normaux float32 (< 2^-126) sont tous
            // en dessous du plus petit sous-normal half (2^-24).
            return if (mant32 == 0) sign else null
        }

        val unbiased = exp32 - 127
        if (unbiased in -14..15) {
            // Normal en half : 10 bits de mantisse, les 13 bas doivent être nuls.
            if (mant32 and 0x1FFF != 0) return null
            return sign or ((unbiased + 15) shl 10) or (mant32 ushr 13)
        }
        if (unbiased in -24..-15) {
            // Sous-normal en half : valeur = m × 2^-24, m sur 10 bits.
            val m = 0x80_0000 or mant32
            val shift = -unbiased - 1
            if (m and ((1 shl shift) - 1) != 0) return null
            return sign or (m ushr shift)
        }
        return null
    }

    private const val MAJOR_UINT = 0
    private const val MAJOR_NINT = 1
    private const val MAJOR_BYTES = 2
    private const val MAJOR_TEXT = 3
    private const val MAJOR_ARRAY = 4
    private const val MAJOR_MAP = 5
    private const val MAJOR_TAG = 6
}
