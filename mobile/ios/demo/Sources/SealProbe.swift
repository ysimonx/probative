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

    /// Les deux points d'entrée du cœur (spec §2.5), et donc les deux profils.
    ///
    /// La séquence est la même de bout en bout — enrôlement, nonce,
    /// scellement, verdict — et seul le quatrième temps diffère. C'est
    /// exactement ce que le format promet : `capture` est le noyau plus des
    /// exigences, pas un mécanisme séparé.
    enum Mode {
        case core, capture

        var profile: String {
            switch self {
            case .core: return CorePayload.profile
            case .capture: return CapturePayload.profile
            }
        }
    }

    /// Exécute la séquence complète. Ne lance jamais : un échec est une ligne
    /// du journal, pas une exception qui masquerait les étapes déjà franchies.
    static func run(_ mode: Mode = .core) async -> [Line] {
        var lines: [Line] = []
        func ok(_ s: String) {
            lines.append(Line(text: s, failed: false))
            print("[probe] \(s)")
        }
        func ko(_ s: String) {
            lines.append(Line(text: s, failed: true))
            print("[probe] ECHEC \(s)")
        }

        // Le journal doit se lire sans l'écran : l'état des autorisations est
        // déjà en tête (posé par `ProbeView`), et la première ligne dit quelle
        // sonde a produit ce qui suit.
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        switch mode {
        case .core:
            ok("probative — sonde C4.1 : enveloppe complete, profil core")
        case .capture:
            ok("probative — sonde C4.2 : acquisition photo, profil capture")
        }
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
                profile: mode.profile
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
            guard profile == mode.profile else {
                ko("nonce emis pour \(profile), ce sceau produit \(mode.profile)")
                return lines
            }

            // ── 4. Scellement ─────────────────────────────────────────────
            let sealer = Sealer(
                deployment: deployment,
                signingKey: signingKey,
                appVersion: version ?? "0.1",
                freshness: AppAttestFreshness(keyId: keyId)
            )
            let sealed: SealedEnvelope
            let media: Data
            switch mode {
            case .core:
                let sealStart = DispatchTime.now().uptimeNanoseconds
                sealed = try await sealer.seal(
                    content: content,
                    mimeType: contentType,
                    nonce: nonce
                )
                media = content
                ok("scellement       \(since(sealStart))")
            case .capture:
                // La sonde déroule l'acquisition étape par étape plutôt que
                // d'appeler `capture()`, pour pouvoir chronométrer et
                // rapporter chacune. Un intégrateur, lui, appelle `capture()`.
                let (envelope, jpeg) = try await acquire(sealer: sealer, nonce: nonce, ok: ok)
                sealed = envelope
                media = jpeg
            }
            ok("charge utile     \(sealed.payloadBytes.count) octets")
            ok("defi R1          \(sealed.challenge.base64EncodedString())")
            ok("enveloppe        \(sealed.bytes.count) octets")

            // ── 5. Verdict ────────────────────────────────────────────────
            let verifyStart = DispatchTime.now().uptimeNanoseconds
            let result = try await server.verify(envelope: sealed.bytes, media: media)
            ok("verification     \(since(verifyStart))")
            lines.append(contentsOf: report(result))
        } catch let failure as DevServer.Failure {
            ko("serveur \(failure.description)")
        } catch let described as CustomStringConvertible {
            // Une énumération Swift pontée en `NSError` perd son message et
            // ne rend plus que « code 0 », ce qui n'apprend rien. Les erreurs
            // du cœur portent toutes une description : on la privilégie.
            ko(described.description)
        } catch {
            ko("\((error as NSError).domain) code \((error as NSError).code) — \(error.localizedDescription)")
        }
        return lines
    }

    /// L'acquisition, déroulée pour être chronométrée étape par étape.
    ///
    /// Trois mesures qu'aucune autre étape ne donne : le coût de la capture
    /// elle-même, celui du point de position, et celui de la corroboration.
    /// C'est le vrai sujet de l'inconnue n° 2 — la fraîcheur, elle, ne coûte
    /// rien et on le sait depuis A5.
    private static func acquire(
        sealer: Sealer,
        nonce: Data,
        ok: (String) -> Void
    ) async throws -> (SealedEnvelope, Data) {
        // Position et corroboration courent PENDANT l'acquisition, comme le
        // fait `capture()`. Les enchaîner après l'obturateur gonflait
        // `media[6]` de 4,2 s et faisait tomber `origin` à C : mesuré, puis
        // corrigé.
        let start = DispatchTime.now().uptimeNanoseconds
        async let fixTask = Sensors.location()
        async let claimsTask = Sensors.claims()

        let image = try await Camera.capture()
        ok("capture          \(since(start)) — \(image.jpeg.count) octets, "
            + "\(image.pixelSize.width)x\(image.pixelSize.height)")

        let claims = await claimsTask
        ok("corroboration    \(since(start)) cumule — "
            + (claims.isEmpty ? "aucune" : claims.map(\.type).joined(separator: ", ")))

        guard let fix = await fixTask else {
            throw CaptureError.noPosition
        }
        let shutterDate = Date(
            timeIntervalSinceNow: image.shutterUptime - ProcessInfo.processInfo.systemUptime
        )
        let position = Sensors.position(from: fix, shutterDate: shutterDate)
        ok("position         \(since(start)) cumule — \(position.provider.rawValue), "
            + String(format: "%.0f m, age %d ms", position.horizontalAccuracy, position.fixAgeMs))
        // Sur iOS, l'absence d'indicateur de position simulée est
        // structurelle : sans `motion` ni `steps`, le vérificateur plafonne
        // `position` à C. Le dire ici évite de chercher la cause dans le
        // verdict.
        if !claims.contains(where: { $0.type == "motion" || $0.type == "steps" }) {
            ok("                 sans corroboration inertielle, position plafonne a C")
        }

        let sealStart = DispatchTime.now().uptimeNanoseconds
        let sealed = try await sealer.seal(
            image: image, position: position, claims: claims, nonce: nonce
        )
        ok("scellement       \(since(sealStart))")
        return (sealed, image.jpeg)
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
