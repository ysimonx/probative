import CryptoKit
import Foundation
import ProbativeCore
import UIKit

/// Sonde **C4.1** — la boucle complète « appareil → enveloppe → verdict
/// serveur », profil `core`, sans caméra. Pendant iOS de la sonde A4.1.
///
/// Elle remplace la sonde C3, dont elle est un sur-ensemble strict : C3
/// s'arrêtait à une assertion sur une charge utile de substitution, et le
/// pipeline ne pouvait donc pas rejouer son vecteur. Ici l'assertion porte sur
/// le défi R1 d'une vraie enveloppe `COSE_Sign1`, qui part se faire juger.
///
/// Elle ne juge rien (invariant 1). Le seul verdict affiché est celui que le
/// serveur renvoie ; rien ici ne le calcule, ne l'anticipe ni ne le résume.
enum SealProbe {

    /// Étiquette du trousseau pour la clé d'enveloppe. **Distincte de la clé
    /// App Attest**, qui vit dans son propre espace géré par DeviceCheck —
    /// confondre les deux bloque net, et c'est la première chose que la
    /// phase D a apprise.
    private static let signingTag = Data("org.probative.demo.signing".utf8)

    /// Identifiant de déploiement — celui des vecteurs, pour un serveur de dev.
    private static let deployment = "test-deployment"

    /// Les octets à sceller. N'importe lesquels feraient l'affaire : le noyau
    /// n'affirme rien de leur provenance, et c'est exactement ce que cette
    /// étape doit montrer.
    private static let content = Data("probative — octets remis au scellement, sonde C4.1\n".utf8)
    private static let contentType = "text/plain"

    struct Line: Identifiable {
        let id = UUID()
        let text: String
        let failed: Bool
    }

    /// Exécute la séquence complète. Ne lance jamais : un échec est une ligne
    /// du journal, pas une exception qui masquerait les étapes déjà franchies.
    static func run() async -> [Line] {
        var lines: [Line] = []
        func ok(_ s: String) {
            lines.append(Line(text: s, failed: false))
            print("[probe] \(s)")
        }
        func ko(_ s: String) {
            lines.append(Line(text: s, failed: true))
            print("[probe] ECHEC \(s)")
        }

        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        ok("probative — sonde C4.1 : enveloppe complete, profil core")
        ok("version \(version ?? "?") — iOS \(UIDevice.current.systemVersion)")

        guard let server = DevServer.fromBundle() else {
            ko("adresse du serveur absente de l'Info.plist — regenerer le projet")
            return lines
        }
        ok("serveur \(server.baseURL.absoluteString)")

        guard AppAttest.isSupported else {
            // Pas de version dégradée : sans assertion, l'enveloppe n'aurait
            // aucune preuve de fraîcheur.
            ko("App Attest indisponible — appareil reel requis")
            return lines
        }

        do {
            // ── 1. Les deux clés ──────────────────────────────────────────
            SigningKey.delete(tag: signingTag)
            let start = DispatchTime.now().uptimeNanoseconds
            let signingKey = try SigningKey.create(tag: signingTag)
            ok("cle d'enveloppe  enclave: \(signingKey.secureEnclave), \(since(start))")

            let keyStart = DispatchTime.now().uptimeNanoseconds
            let keyId = try await AppAttest.generateKey()
            ok("cle App Attest   \(since(keyStart))")

            // ── 2. Enrôlement ─────────────────────────────────────────────
            //
            // Le défi d'enrôlement vient du serveur dans une boucle réelle ;
            // ici il est tiré au sort par l'appareil, comme côté Android. Ce
            // que le serveur vérifie est la liaison : `clientDataHash` vaut
            // SHA-256 du défi, et il refait le calcul.
            var challenge = Data(count: 16)
            _ = challenge.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
            }
            let attestStart = DispatchTime.now().uptimeNanoseconds
            let attestation = try await AppAttest.attest(
                keyId: keyId,
                clientDataHash: Data(SHA256.hash(data: challenge))
            )
            ok("attestation      \(attestation.count) octets, \(since(attestStart))")

            let enrolled = try await server.enroll(
                publicKeyX962: try signingKey.publicKeyX962(),
                keyId: Data(base64Encoded: keyId) ?? Data(),
                attestation: attestation,
                challenge: challenge
            )
            ok("enrolement       kid \(enrolled["kid_hex"] as? String ?? "?")")
            // `attested: false` signifierait que la clé a été acceptée sur
            // parole — le mode dégradé du serveur, qui ne prouve rien.
            ok("                 attestation validee : \(enrolled["attested"] as? Bool ?? false)")

            // ── 3. Nonce, émis pour le profil ─────────────────────────────
            let issued = try await server.nonce(
                kid: try signingKey.kid(),
                profile: CorePayload.profile
            )
            guard
                let nonce = Data(base64Encoded: issued["nonce_b64"] as? String ?? ""),
                let profile = issued["profile"] as? String
            else {
                ko("reponse /nonce inexploitable")
                return lines
            }
            ok("nonce            \(nonce.count) octets, profil \(profile)")
            // Le profil signé doit être celui du nonce : mieux vaut s'arrêter
            // que faire signer une enveloppe que le serveur rejettera pour
            // cette raison.
            guard profile == CorePayload.profile else {
                ko("nonce emis pour \(profile), ce sceau produit \(CorePayload.profile)")
                return lines
            }

            // ── 4. Scellement ─────────────────────────────────────────────
            let sealer = Sealer(
                deployment: deployment,
                signingKey: signingKey,
                appVersion: version ?? "0.1",
                freshness: AppAttestFreshness(keyId: keyId)
            )
            let sealStart = DispatchTime.now().uptimeNanoseconds
            let sealed = try await sealer.seal(
                content: content,
                mimeType: contentType,
                nonce: nonce
            )
            ok("scellement       \(since(sealStart))")
            ok("charge utile     \(sealed.payloadBytes.count) octets")
            ok("defi R1          \(sealed.challenge.base64EncodedString())")
            ok("enveloppe        \(sealed.bytes.count) octets")

            // ── 5. Verdict ────────────────────────────────────────────────
            let verifyStart = DispatchTime.now().uptimeNanoseconds
            let result = try await server.verify(envelope: sealed.bytes, media: content)
            ok("verification     \(since(verifyStart))")
            lines.append(contentsOf: report(result))
        } catch let failure as DevServer.Failure {
            ko("serveur \(failure.description)")
        } catch {
            ko("\((error as NSError).domain) code \((error as NSError).code) — \(error.localizedDescription)")
        }
        return lines
    }

    /// Le résultat, propriété par propriété. Ni `level` seul, ni résumé
    /// maison : le format de sortie du vérificateur est structuré pour une
    /// raison, et l'aplatir ferait perdre exactement ce que `level_reason`
    /// sert à rendre exploitable.
    private static func report(_ result: [String: Any]) -> [Line] {
        var lines: [Line] = []
        func add(_ s: String, failed: Bool = false) {
            lines.append(Line(text: s, failed: failed))
            print("[probe] \(s)")
        }

        let level = result["level"] as? String ?? "?"
        add("niveau           \(level)", failed: level == "UNTRUSTED")
        add("motif            \(result["level_reason"] as? String ?? "")")
        add("profil juge      \(result["profile"] as? String ?? "?")")
        for (name, value) in (result["properties"] as? [String: Any] ?? [:]).sorted(by: {
            $0.key < $1.key
        }) {
            let property = value as? [String: Any] ?? [:]
            let grade = property["grade"] as? String ?? "?"
            let evidence = (property["evidence"] as? [String] ?? []).joined(separator: ",")
            add("  \(name.padding(toLength: 14, withPad: " ", startingAt: 0)) \(grade)  \(evidence)",
                failed: grade == "F")
        }
        let flags = (result["flags"] as? [String] ?? []).joined(separator: ", ")
        add("drapeaux         \(flags.isEmpty ? "aucun" : flags)")
        return lines
    }

    private static func since(_ start: UInt64) -> String {
        String(format: "%.0f ms", Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
    }
}
