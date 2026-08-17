package org.probative.core.freshness

/**
 * Source de preuve de fraîcheur — ce qui remplit le label 200 de l'en-tête
 * non protégé.
 *
 * L'assemblage d'enveloppe ne connaît que cette interface : il ne doit
 * dépendre ni de Play Integrity, ni d'App Attest, ni de ce qui viendra.
 * C'est aussi ce qui permet à un test d'exercer le chemin complet sans
 * appeler les serveurs de Google.
 *
 * Le jeton est **opaque** : rien ici ne le lit, ne le décode et n'en déduit
 * un booléen de confiance (invariant 1).
 */
interface FreshnessSource {

    /**
     * Valeur du label 1 de `freshness` — `"play-integrity"`, `"app-attest"`,
     * ou `"key-attestation"` pour une capture hors ligne (ADR-0010).
     */
    val kind: String

    /**
     * Jeton lié au défi R1, qui vaut exactement `SHA-256(payload ‖ nonce)`.
     *
     * L'implémentation ne doit **jamais** demander un jeton sur autre chose :
     * sans cette liaison, le jeton atteste seulement qu'un appareil sain
     * existe quelque part (invariant 2).
     *
     * Bloquant — appelé hors du fil principal.
     */
    fun token(challenge: ByteArray): ByteArray
}

/**
 * Fraîcheur Android : un jeton de l'API standard Play Integrity, dont le
 * `requestHash` porte le défi R1.
 *
 * Le jeton de Play est une **chaîne** ASCII là où le format attend une chaîne
 * d'octets ; la conversion est ici, en un seul endroit, plutôt que dispersée
 * chez les appelants. Le vérificateur fait le chemin inverse et refuse tout
 * ce qui n'est pas de l'ASCII.
 */
class PlayIntegrityFreshness(
    private val provider: PlayIntegrity.Provider,
) : FreshnessSource {

    override val kind: String get() = KIND

    override fun token(challenge: ByteArray): ByteArray =
        PlayIntegrity.token(provider, challenge).toByteArray(Charsets.US_ASCII)

    companion object {
        const val KIND = "play-integrity"
    }
}
