package org.probative.core.cbor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Conformité de l'encodeur aux exemples normatifs (RFC 8949, annexe A).
 * Les vecteurs d'or du vérificateur couvrent le format réel ; ces cas
 * couvrent les frontières que le format n'exerce pas encore.
 */
class CborTest {

    private fun hex(value: Any): String =
        Cbor.encode(value).joinToString("") { "%02x".format(it) }

    @Test
    fun `entiers en forme la plus courte`() {
        assertEquals("00", hex(0))
        assertEquals("17", hex(23))
        assertEquals("1818", hex(24))
        assertEquals("1864", hex(100))
        assertEquals("1a000f4240", hex(1_000_000))
        assertEquals("1b000000e8d4a51000", hex(1_000_000_000_000L))
        assertEquals("20", hex(-1))
        assertEquals("3903e7", hex(-1000))
    }

    @Test
    fun `flottants en forme la plus courte`() {
        assertEquals("f90000", hex(0.0))
        assertEquals("f98000", hex(-0.0))
        assertEquals("f93c00", hex(1.0))
        assertEquals("f93e00", hex(1.5))
        assertEquals("f97bff", hex(65504.0))
        assertEquals("f90001", hex(5.960464477539063e-8))
        assertEquals("f90400", hex(0.00006103515625))
        assertEquals("f9c400", hex(-4.0))
        assertEquals("fa47c35000", hex(100000.0))
        assertEquals("fa7f7fffff", hex(3.4028234663852886e38))
        assertEquals("fb3ff199999999999a", hex(1.1))
        assertEquals("f97c00", hex(Double.POSITIVE_INFINITY))
        assertEquals("f9fc00", hex(Double.NEGATIVE_INFINITY))
        assertEquals("f97e00", hex(Double.NaN))
    }

    @Test
    fun `chaines octets tableaux`() {
        assertEquals("60", hex(""))
        assertEquals("6449455446", hex("IETF"))
        assertEquals("4401020304", hex(byteArrayOf(1, 2, 3, 4)))
        assertEquals("80", hex(emptyList<Any>()))
        assertEquals("83010203", hex(listOf(1, 2, 3)))
    }

    @Test
    fun `maps triees par octets d'encodage`() {
        assertEquals("a0", hex(emptyMap<Int, Any>()))
        // L'ordre d'insertion est inversé : le tri canonique doit primer.
        assertEquals("a20a021864 01".replace(" ", ""), hex(linkedMapOf(100 to 1, 10 to 2)))
    }

    @Test
    fun `tag transparent`() {
        assertEquals("d280", hex(CborTag(18, emptyList<Any>())))
    }

    @Test
    fun `types hors format rejetes`() {
        assertThrows(IllegalArgumentException::class.java) { Cbor.encode(mapOf("a" to 1)) }
        assertThrows(IllegalArgumentException::class.java) { Cbor.encode(0.5f) }
        assertThrows(IllegalArgumentException::class.java) { Cbor.encode(setOf(1)) }
    }
}
