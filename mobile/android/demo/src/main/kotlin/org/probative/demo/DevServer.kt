package org.probative.demo

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject

/**
 * Client des trois routes du serveur de développement
 * (`python -m probative.devserver`).
 *
 * Il vit dans `:demo` et non dans `:core`, à dessein : le cœur ne doit
 * connaître aucun protocole de transport. Un intégrateur envoie l'enveloppe
 * par où il veut — le verdict ne dépend jamais du canal (invariant 7), et
 * l'enveloppe s'authentifie par elle-même.
 *
 * `adb reverse tcp:8765 tcp:8765` est le chemin recommandé : aucune adresse
 * IP à relever, et le serveur n'est pas exposé au réseau local.
 *
 * Bloquant — jamais sur le fil principal.
 */
class DevServer(private val baseUrl: String) {

    class Refused(val status: Int, val detail: String) :
        RuntimeException("$status : $detail")

    /**
     * Enrôlement : la clé publique et **la chaîne d'attestation qui la
     * couvre**. Le défi est celui passé à la génération de la clé ; le perdre
     * rendrait la chaîne invérifiable, puisque le serveur le recalcule contre
     * ce que le TEE a inscrit dans l'extension d'attestation.
     */
    fun enroll(
        publicKeyX962: ByteArray,
        chain: List<ByteArray>?,
        challenge: ByteArray,
    ): JSONObject {
        val body = JSONObject()
            .put("public_key_x962_b64", b64(publicKeyX962))
            .put("platform", "android")
            .put("challenge_b64", b64(challenge))
        if (chain != null) {
            // Feuille en tête, racine en queue — l'ordre du Keystore.
            body.put("attestation_chain_b64", JSONArray(chain.map { b64(it) }))
        } else {
            // `chain` nul : la clé est enrôlée **sur parole**, et la réponse le
            // dit (`attested: false`). C'est le mode dégradé du serveur de dev,
            // réservé à une répétition sur émulateur — il n'atteste rien.
            //
            // `hardware_backed` est explicitement démenti, et ce n'est pas un
            // détail : le serveur le suppose vrai par défaut, si bien qu'une
            // clé logicielle d'émulateur ressortait notée
            // `key-attested-hardware` et hissait `integrity` en A. Une
            // répétition qui flatte le résultat est pire qu'une répétition
            // qui échoue.
            body.put("hardware_backed", false)
        }
        return post("/enroll", body)
    }

    /**
     * Nonce, émis **pour un profil**. La réponse porte ce profil : c'est lui
     * que l'enveloppe doit déclarer, et non celui que le client aurait choisi.
     */
    fun nonce(kid: ByteArray, profile: String): JSONObject = post(
        "/nonce",
        JSONObject().put("kid_b64", b64(kid)).put("profile", profile),
    )

    /**
     * Vérification. Les octets du média accompagnent l'enveloppe : sans eux,
     * le serveur ne peut pas recalculer l'empreinte de `media[2]` — il ne
     * lui resterait que la parole du client sur ce qu'il a scellé.
     */
    fun verify(envelope: ByteArray, media: ByteArray): JSONObject = post(
        "/verify",
        JSONObject().put("envelope_b64", b64(envelope)).put("media_b64", b64(media)),
    )

    private fun post(path: String, body: JSONObject): JSONObject {
        val connection = (URL("$baseUrl$path").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = 10_000
            readTimeout = 30_000
        }
        return try {
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            val status = connection.responseCode
            if (status != 200) {
                // Le corps d'erreur porte le motif du refus, seul contenu
                // exploitable : un code seul enverrait chercher au mauvais
                // endroit. Il arrive par `errorStream`, que `inputStream`
                // ne rend pas.
                val detail = connection.errorStream?.use { it.readBytes().decodeToString() }
                throw Refused(status, detail ?: "corps vide")
            }
            JSONObject(connection.inputStream.use { it.readBytes().decodeToString() })
        } finally {
            connection.disconnect()
        }
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
}
