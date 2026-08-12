package org.probative.core.keys

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.Signature
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import android.util.Base64

/**
 * Sortie de l'étape A3 — s'exécute sur appareil réel uniquement
 * (l'émulateur ne rend pas de clé matérielle représentative) :
 *
 *     ./gradlew :core:connectedDebugAndroidTest
 *
 * Le test d'enrôlement complet exige en plus le serveur de dev joignable
 * depuis l'appareil. `adb reverse` est préférable à `--host 0.0.0.0` :
 * aucune adresse IP à relever, appareil et hôte n'ont pas besoin d'être sur
 * le même réseau, et le serveur n'est pas exposé au réseau local.
 *
 *     python -m probative.devserver --port 8765   # sur l'hôte
 *     adb reverse tcp:8765 tcp:8765
 *     ./gradlew :core:connectedDebugAndroidTest \
 *       -Pandroid.testInstrumentationRunnerArguments.probative.devserver=http://127.0.0.1:8765
 *
 * Vérifier le journal du serveur (`POST /enroll 200`) et le compte de tests
 * sautés : `assumeTrue` escamote silencieusement l'enrôlement si l'argument
 * `probative.devserver` manque, et la campagne passe alors au vert sans
 * avoir rien enrôlé.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreKeysDeviceTest {

    private val alias = "probative-test-${System.currentTimeMillis()}"

    @After
    fun cleanup() {
        if (KeystoreKeys.exists(alias)) KeystoreKeys.delete(alias)
    }

    private fun freshChallenge(): ByteArray =
        ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun cle_materielle_exportable_et_attestee() {
        val generated = KeystoreKeys.generate(alias, freshChallenge())

        // Critère A3 : la clé réside dans du matériel. SOFTWARE est un
        // échec — l'appareil ne convient pas au spike.
        val level = KeystoreKeys.securityLevel(alias)
        assertTrue(
            "clé non matérielle : $level",
            level in setOf(
                KeystoreKeys.SecurityLevel.STRONGBOX,
                KeystoreKeys.SecurityLevel.TRUSTED_ENVIRONMENT,
            ),
        )
        if (generated.strongBox) {
            assertEquals(KeystoreKeys.SecurityLevel.STRONGBOX, level)
        }

        val x962 = KeystoreKeys.publicKeyX962(alias)
        assertEquals(65, x962.size)
        assertEquals(4.toByte(), x962[0])
        assertEquals(32, KeystoreKeys.kid(alias).size)

        // Chaîne d'attestation : au moins feuille + intermédiaire + racine
        // sur un appareil certifié. Sa validation est la phase B.
        assertTrue(KeystoreKeys.certificateChain(alias).size >= 2)
    }

    @Test
    fun signature_brute_verifiable() {
        KeystoreKeys.generate(alias, freshChallenge())
        val message = "octets a signer sur appareil".toByteArray()

        val raw = KeystoreKeys.signRaw(alias, message)
        assertEquals(64, raw.size)

        // Android n'expose pas le format P1363 : on reconstruit le DER.
        val der = derSignature(raw)
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(KeystoreKeys.publicKey(alias))
            update(message)
            verify(der)
        }
        assertTrue("signature convertie refusée", valid)
    }

    @Test
    fun enrolement_contre_le_serveur_de_dev() {
        val base = InstrumentationRegistry.getArguments().getString("probative.devserver")
        assumeTrue("argument probative.devserver absent : test d'enrôlement sauté", base != null)

        // Le défi doit survivre à la génération : le serveur le recalculera
        // contre celui que le TEE a inscrit dans l'extension d'attestation.
        // Le perdre ici rendrait la chaîne invérifiable.
        val challenge = freshChallenge()
        KeystoreKeys.generate(alias, challenge)

        val chain = KeystoreKeys.certificateChain(alias)
        assertTrue("chaîne trop courte : ${chain.size}", chain.size >= 2)

        val body = JSONObject()
            .put(
                "public_key_x962_b64",
                Base64.encodeToString(KeystoreKeys.publicKeyX962(alias), Base64.NO_WRAP),
            )
            .put("platform", "android")
            // Feuille en tête, racine en queue — c'est l'ordre que rend le
            // Keystore et celui qu'attend le serveur.
            .put("attestation_chain_b64", JSONArray(chain.map { b64(it) }))
            .put("challenge_b64", b64(challenge))

        val connection = URL("$base/enroll").openConnection() as HttpURLConnection
        val response = try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            assertEquals(200, connection.responseCode)
            connection.inputStream.use { JSONObject(it.readBytes().decodeToString()) }
        } finally {
            connection.disconnect()
        }

        // Le serveur et l'appareil doivent calculer le même kid (règle R2).
        assertEquals(
            response.getString("kid_hex"),
            KeystoreKeys.kid(alias).joinToString("") { "%02x".format(it) },
        )

        // Le critère de cette étape : le serveur a validé la chaîne jusqu'à
        // une racine publiée par Google, et a établi que cette chaîne porte
        // bien sur la clé enrôlée. `false` signifierait que la clé a été
        // acceptée sur parole — le mode dégradé, pas ce qu'on exerce ici.
        assertTrue(
            "chaîne non attestée par le serveur",
            response.getBoolean("attested"),
        )
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    /** DER `ECDSA-Sig-Value` minimal depuis `r‖s` — l'inverse de Cose. */
    private fun derSignature(raw: ByteArray): ByteArray {
        fun integer(bytes: ByteArray): ByteArray {
            val value = BigInteger(1, bytes).toByteArray()
            return byteArrayOf(0x02, value.size.toByte()) + value
        }

        val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return ByteArrayOutputStream().apply {
            write(0x30)
            write(body.size)
            write(body)
        }.toByteArray()
    }
}
