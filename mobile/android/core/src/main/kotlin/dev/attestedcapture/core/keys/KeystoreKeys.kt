package dev.attestedcapture.core.keys

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import dev.attestedcapture.core.cose.Cose
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Clé de signature d'enveloppe dans le Keystore Android.
 *
 * La clé est générée avec `setAttestationChallenge(nonce)` : la chaîne
 * de certificats retournée prouve au serveur que la clé réside dans du
 * matériel et que la génération répondait à son défi (enrôlement,
 * spec §1.1). La validation de cette chaîne est côté serveur, phase B —
 * ici on collecte et on transmet, on ne juge rien (invariant 1).
 *
 * StrongBox est demandé d'abord, avec repli TEE : le repli n'est jamais
 * silencieux côté serveur, puisque le niveau réel se relit dans la
 * chaîne d'attestation, pas dans ce que déclare le client.
 */
object KeystoreKeys {

    enum class SecurityLevel { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN }

    data class Generated(val alias: String, val strongBox: Boolean)

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    fun generate(alias: String, attestationChallenge: ByteArray): Generated {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateInternal(alias, attestationChallenge, strongBox = true)
                return Generated(alias, strongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                // Repli TEE ci-dessous.
            } catch (_: ProviderException) {
                // Certains appareils signalent l'absence de StrongBox par
                // une ProviderException générique plutôt que par
                // l'exception dédiée. Même repli.
            }
        }
        generateInternal(alias, attestationChallenge, strongBox = false)
        return Generated(alias, strongBox = false)
    }

    private fun generateInternal(alias: String, challenge: ByteArray, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // La signature part en arrière-plan juste après la capture :
            // exiger un déverrouillage utilisateur ruinerait la latence
            // capture→signature (media.6) sans rien prouver de plus.
            .setUserAuthenticationRequired(false)
            .setAttestationChallenge(challenge)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    fun exists(alias: String): Boolean = keyStore().containsAlias(alias)

    fun delete(alias: String) = keyStore().deleteEntry(alias)

    fun publicKey(alias: String): ECPublicKey {
        val certificate = keyStore().getCertificate(alias)
            ?: throw IllegalStateException("aucune clé sous l'alias $alias")
        return certificate.publicKey as ECPublicKey
    }

    fun publicKeyX962(alias: String): ByteArray = EcPublicKeys.x962Uncompressed(publicKey(alias))

    fun kid(alias: String): ByteArray = EcPublicKeys.kid(publicKey(alias))

    /** Chaîne d'attestation complète, DER, feuille en premier. */
    fun certificateChain(alias: String): List<ByteArray> =
        keyStore().getCertificateChain(alias)?.map { it.encoded }
            ?: throw IllegalStateException("aucune chaîne sous l'alias $alias")

    /** Niveau de sécurité *déclaré par l'appareil* — indicatif seulement,
     *  le niveau opposable est celui de la chaîne d'attestation. */
    fun securityLevel(alias: String): SecurityLevel {
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("aucune clé privée sous l'alias $alias")
        val info = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
                -> SecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
                else -> SecurityLevel.UNKNOWN
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) {
            SecurityLevel.TRUSTED_ENVIRONMENT
        } else {
            SecurityLevel.SOFTWARE
        }
    }

    /** Signe `data` et rend la signature brute `r‖s` attendue par COSE. */
    fun signRaw(alias: String, data: ByteArray): ByteArray {
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("aucune clé privée sous l'alias $alias")
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
        return Cose.rawSignatureFromDer(der)
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
