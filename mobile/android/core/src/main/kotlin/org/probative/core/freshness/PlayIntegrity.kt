package org.probative.core.freshness

import android.content.Context
import android.util.Base64
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest

/**
 * Enveloppe mince de l'API standard Play Integrity — la preuve de fraîcheur
 * Android, pendant de `AppAttest` côté iOS.
 *
 * Aucune décision ici : le jeton part opaque au serveur, qui le valide en
 * phase B (invariant 1). Le cœur ne lit jamais son contenu et n'en déduit
 * jamais un booléen de confiance.
 *
 * Différence de nature avec iOS, à garder en tête : `DeviceCheck` est un
 * framework système, alors que Play Integrity est une bibliothèque Google
 * Play. L'AAR en hérite donc une dépendance externe — c'est le seul chemin
 * vers une attestation d'*application* sur Android, et c'est assumé.
 */
object PlayIntegrity {

    /** Plafond documenté par Google pour le `requestHash`. */
    const val MAX_REQUEST_HASH_LENGTH = 500

    /**
     * Fournisseur préparé, opaque.
     *
     * Le type de Play est délibérément encapsulé : la surface publique du cœur
     * ne laisse pas filtrer de type propriétaire, sans quoi tout consommateur —
     * la démonstration, et demain les liaisons Flutter et React Native — devrait
     * embarquer Play Integrity à la compilation pour nommer ce type.
     */
    class Provider internal constructor(
        internal val delegate: StandardIntegrityTokenProvider,
    )

    /**
     * Encodage du défi R1 vers le `requestHash`, qui est une **chaîne** là où
     * R1 produit 32 octets bruts (inconnue n° 1 du spike).
     *
     * base64url sans bourrage : 43 caractères pour 32 octets, très en deçà du
     * plafond, sûr en URL, et sans caractère que l'API pourrait normaliser.
     * L'hexadécimal conviendrait aussi mais coûte 64 caractères pour la même
     * information. Ce choix doit devenir normatif dans ADR-0002 une fois
     * validé sur appareil — un encodage qui diffère entre client et serveur
     * casse silencieusement la règle R1.
     */
    fun encodeRequestHash(challenge: ByteArray): String =
        Base64.encodeToString(
            challenge,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )

    /**
     * Prépare le fournisseur de jetons. Opération coûteuse, à lancer au
     * démarrage et à conserver : la refaire à chaque capture ajouterait sa
     * latence au chemin capture→signature, que `media.6` doit garder court.
     *
     * Bloquant — à appeler hors du fil principal.
     */
    fun prepare(context: Context, cloudProjectNumber: Long): Provider {
        require(cloudProjectNumber > 0) {
            "numéro de projet Google Cloud absent — voir la propriété Gradle " +
                "probative.cloudProjectNumber"
        }
        val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
        return Provider(
            Tasks.await(
                manager.prepareIntegrityToken(
                    PrepareIntegrityTokenRequest.builder()
                        .setCloudProjectNumber(cloudProjectNumber)
                        .build(),
                ),
            ),
        )
    }

    /**
     * Jeton lié au défi R1. Le `requestHash` vaut exactement l'encodage de
     * `SHA-256(payload_bytes ‖ nonce)` — jamais autre chose, jamais rien
     * (règle R1, non négociable) : sans lui le jeton atteste seulement qu'un
     * appareil sain existe quelque part.
     *
     * Bloquant — à appeler hors du fil principal.
     */
    fun token(provider: Provider, challenge: ByteArray): String {
        val requestHash = encodeRequestHash(challenge)
        check(requestHash.length <= MAX_REQUEST_HASH_LENGTH) {
            "requestHash de ${requestHash.length} caractères, plafond $MAX_REQUEST_HASH_LENGTH"
        }
        return Tasks.await(
            provider.delegate.request(
                StandardIntegrityTokenRequest.builder()
                    .setRequestHash(requestHash)
                    .build(),
            ),
        ).token()
    }
}
