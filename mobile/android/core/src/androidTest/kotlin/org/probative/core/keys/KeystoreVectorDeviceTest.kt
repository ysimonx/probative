package org.probative.core.keys

import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest
import java.security.Signature
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Capture du **vecteur d'appareil Android** — pendant exact de la sonde C3
 * côté iOS (`mobile/ios/demo`).
 *
 * Ce test ne valide rien de la chaîne d'attestation : c'est la phase B, et
 * l'écrire sans avoir vu une chaîne authentique reviendrait à coder contre
 * une documentation. Il collecte, et rend les octets récupérables :
 *
 *     ./gradlew :core:connectedDebugAndroidTest \
 *       -Pandroid.testInstrumentationRunnerArguments.class=org.probative.core.keys.KeystoreVectorDeviceTest
 *     adb logcat -d -s PROBATIVE_VECTOR
 *
 * Le vecteur ressort par **logcat**, en tronçons, et non par un fichier :
 * Gradle désinstalle le paquet de test à la fin de la campagne, ce qui
 * emporte son répertoire de données, et depuis Android 11 `adb` ne peut de
 * toute façon plus lire `Android/data` d'une autre application. Le tampon
 * logcat, lui, survit à la désinstallation.
 *
 * Le défi d'attestation est un **vrai R1**, `SHA-256(payload ‖ nonce)`, et
 * ses deux composants partent en clair dans le vecteur. C'est ce qui rend la
 * liaison vérifiable par recalcul : Keystore recopie le défi dans l'extension
 * d'attestation du certificat feuille, un vérificateur doit pouvoir le
 * retrouver lui-même plutôt que de croire le client sur parole.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreVectorDeviceTest {

    private val alias = "probative-vector-${System.currentTimeMillis()}"

    private companion object {
        const val TAG = "PROBATIVE_VECTOR"
    }

    @After
    fun cleanup() {
        if (KeystoreKeys.exists(alias)) KeystoreKeys.delete(alias)
    }

    @Test
    fun capture_le_vecteur_d_appareil() {
        // Charge utile de substitution : la capture réelle est l'étape A4.
        // Ce qui compte ici est que le défi soit calculé, pas tiré au hasard.
        val payload = "charge utile de substitution — vecteur A3".toByteArray()
        val nonce = ByteArray(16) { ((it * 7) + 3).toByte() }
        val challenge = MessageDigest.getInstance("SHA-256").digest(payload + nonce)
        assertEquals(32, challenge.size)

        val generateStart = System.nanoTime()
        val generated = KeystoreKeys.generate(alias, challenge)
        val generateMs = (System.nanoTime() - generateStart) / 1_000_000.0

        val level = KeystoreKeys.securityLevel(alias)
        assertTrue("clé non matérielle : $level", level != KeystoreKeys.SecurityLevel.SOFTWARE)

        val chain = KeystoreKeys.certificateChain(alias)
        assertTrue("chaîne trop courte : ${chain.size}", chain.size >= 2)

        // Signature de contrôle : le vecteur doit permettre à la phase B de
        // vérifier une signature réelle, pas seulement de lire des certificats.
        val message = "octets a signer — vecteur A3".toByteArray()
        val signStart = System.nanoTime()
        val raw = KeystoreKeys.signRaw(alias, message)
        val signMs = (System.nanoTime() - signStart) / 1_000_000.0
        assertEquals(64, raw.size)

        val fixture = JSONObject()
            .put("schema", "probative/spike-a3-fixture/1")
            .put(
                "device",
                JSONObject()
                    .put("manufacturer", Build.MANUFACTURER)
                    .put("model", Build.MODEL)
                    .put("androidRelease", Build.VERSION.RELEASE)
                    .put("sdkInt", Build.VERSION.SDK_INT)
                    .put("securityPatch", Build.VERSION.SECURITY_PATCH),
            )
            .put(
                "key",
                JSONObject()
                    .put("securityLevel", level.name)
                    .put("strongBoxRequested", generated.strongBox)
                    .put("publicKeyX962", b64(KeystoreKeys.publicKeyX962(alias)))
                    .put("kid", b64(KeystoreKeys.kid(alias)))
                    .put("generate_ms", generateMs),
            )
            .put(
                "attestation",
                JSONObject()
                    .put("payload", b64(payload))
                    .put("nonce", b64(nonce))
                    .put("challenge", b64(challenge))
                    .put("chain", JSONArray(chain.map { b64(it) })),
            )
            .put(
                "signature",
                JSONObject()
                    .put("message", b64(message))
                    .put("raw", b64(raw))
                    .put("sign_ms", signMs),
            )

        // Copie de confort, tant que le paquet de test survit.
        InstrumentationRegistry.getInstrumentation().targetContext
            .getExternalFilesDir(null)
            ?.let { File(it, "a3-fixture.json").writeText(fixture.toString(2)) }

        // Sortie de référence : logcat, seul canal qui survit à la
        // désinstallation du paquet de test. Une ligne logcat est tronquée
        // au-delà de ~4 000 caractères, d'où le découpage — numéroté, car
        // l'ordre de lecture du tampon n'est pas garanti.
        val compact = fixture.toString()
        val chunks = compact.chunked(2_000)
        Log.i(TAG, "DEBUT ${chunks.size} troncons ${compact.length} caracteres")
        chunks.forEachIndexed { index, chunk -> Log.i(TAG, "$index:$chunk") }
        Log.i(TAG, "FIN niveau=$level chaine=${chain.size} certificats")
    }

    /**
     * Contrôle local avant de figer le vecteur : la signature brute doit se
     * reconvertir en DER et être acceptée. Un vecteur portant une signature
     * invalide ferait échouer la phase B pour la mauvaise raison.
     */
    @Test
    fun la_signature_du_vecteur_est_verifiable() {
        val payload = "charge utile de substitution — vecteur A3".toByteArray()
        val nonce = ByteArray(16) { ((it * 7) + 3).toByte() }
        KeystoreKeys.generate(alias, MessageDigest.getInstance("SHA-256").digest(payload + nonce))

        val message = "octets a signer — vecteur A3".toByteArray()
        val raw = KeystoreKeys.signRaw(alias, message)

        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(KeystoreKeys.publicKey(alias))
            update(message)
            verify(derSignature(raw))
        }
        assertTrue("signature du vecteur refusée", valid)
    }

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    /** DER `ECDSA-Sig-Value` depuis `r‖s` — identique à celui de A3. */
    private fun derSignature(raw: ByteArray): ByteArray {
        fun integer(bytes: ByteArray): ByteArray {
            val value = java.math.BigInteger(1, bytes).toByteArray()
            return byteArrayOf(0x02, value.size.toByte()) + value
        }

        val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
