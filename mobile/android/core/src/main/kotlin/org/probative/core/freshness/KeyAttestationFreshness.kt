package org.probative.core.freshness

import org.probative.core.cbor.Cbor
import org.probative.core.keys.KeystoreKeys

/**
 * Fraîcheur **hors ligne** : une attestation de clé, produite par la puce.
 *
 * Play Integrity exige un aller-retour avec Google — sans réseau, aucun jeton,
 * donc aucune preuve de fraîcheur au sens du format. L'attestation de clé,
 * elle, est produite **localement** par le composant sécurisé : c'est le seul
 * chemin connu pour attester une capture sans connexion (ADR-0010).
 *
 * **R1 est intacte, et c'est tout l'intérêt.** Le mécanisme d'attestation est
 * *conçu* pour recevoir un défi : `setAttestationChallenge(challenge)` fait
 * inscrire par le TEE, dans le certificat feuille, exactement le condensat
 * qu'on lui donne. Le serveur le recalcule et le confronte, comme il le fait
 * du `requestHash` de Play Integrity. Ce n'est donc pas un assouplissement de
 * l'invariant 2 : c'est une autre **source** de la même preuve.
 *
 * Ce qu'elle établit en plus, et qu'aucune campagne en ligne ne donne : le
 * `RootOfTrust` — `deviceLocked`, `verifiedBootState` — vaut **à l'instant de
 * la prise**, là où celui de l'enrôlement peut avoir des semaines et laisse
 * ouvert le scénario « s'enrôler verrouillé, puis déverrouiller ».
 *
 * Ce qu'elle ne peut pas établir : que le binaire est celui que le magasin
 * distribue. Aucune attestation locale ne le dira, et c'est ce que la
 * validation différée récupère quand le réseau revient (ADR-0011).
 */
class KeyAttestationFreshness : FreshnessSource {

    override val kind: String get() = KIND

    /**
     * Engendre une clé portant le défi, et rend sa chaîne de certificats.
     *
     * **La clé est éphémère et distincte de celle qui signe l'enveloppe.**
     * Confondre les deux ferait changer le `kid` à chaque capture — donc un
     * appareil neuf pour le serveur à chaque fois, donc jamais de maillon
     * précédent. Le chaînage y est mort une fois déjà, des semaines durant,
     * sans que le symptôme `CHAIN_FIRST_LINK_UNKNOWN` soit lu pour ce qu'il
     * était.
     *
     * Le tampon rendu est un **tableau CBOR de certificats DER**, feuille en
     * premier — la forme qu'attend `verify_key_attestation` côté serveur. Il
     * est encodé ici plutôt que laissé en liste parce que `freshness[2]` est
     * une chaîne d'octets au format : un tableau nu y serait refusé, et
     * l'admettre aurait demandé d'élargir le CDDL pour rien.
     *
     * Bloquant, et coûteux : la génération d'une clé matérielle se mesure en
     * dizaines de millisecondes à chaud, en centaines à froid. Elle est
     * appelée **après** que `media[6]` est figé — le champ noté ne la voit
     * donc pas — mais elle pèse sur la latence ressentie.
     */
    override fun token(challenge: ByteArray): ByteArray {
        val alias = "$ALIAS_PREFIX${System.nanoTime()}"
        try {
            KeystoreKeys.generate(alias, challenge)
            return Cbor.encode(KeystoreKeys.certificateChain(alias))
        } finally {
            // Sans cette suppression, le trousseau accumulerait une clé par
            // capture — invisible, croissant, et sans personne pour le vider.
            if (KeystoreKeys.exists(alias)) KeystoreKeys.delete(alias)
        }
    }

    companion object {
        const val KIND = "key-attestation"

        /** Préfixe des clés éphémères, pour les distinguer de la clé enrôlée. */
        const val ALIAS_PREFIX = "probative-attest-"
    }
}
