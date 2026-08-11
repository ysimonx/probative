import CryptoKit
import Foundation
import ProbativeCore
import UIKit

/// Sonde C3 — exécute la séquence App Attest sur appareil réel et rapporte
/// des octets bruts, rien d'autre.
///
/// Aucune décision de validité ici (invariant 1) : la sonde ne dit jamais si
/// une attestation est « bonne ». Elle collecte l'objet d'attestation, une
/// assertion liée à un défi R1, et les mesure. C'est le vérificateur qui juge,
/// en phase D — et c'est précisément le vecteur qui lui manque pour être écrit
/// autrement qu'à l'aveugle.
enum AttestProbe {

    /// Étiquette du trousseau pour la clé d'enveloppe. Distincte de la clé
    /// App Attest, qui vit dans son propre espace géré par DeviceCheck.
    private static let signingTag = Data("org.probative.demo.signing".utf8)

    struct Line: Identifiable {
        let id = UUID()
        let text: String
        let failed: Bool
    }

    /// Exécute la séquence complète et rend le journal + le vecteur JSON.
    /// Ne lance jamais : un échec est une ligne du journal, pas une exception
    /// qui masquerait les étapes déjà franchies.
    static func run() async -> (lines: [Line], fixture: Data?) {
        var lines: [Line] = []
        var fixture: [String: Any] = [
            "schema": "probative/spike-c3-fixture/1"
        ]

        func ok(_ s: String) {
            lines.append(Line(text: s, failed: false))
            print("[probe] \(s)")
        }
        func ko(_ s: String) {
            lines.append(Line(text: s, failed: true))
            print("[probe] ECHEC \(s)")
        }

        // Contexte : le vérificateur en aura besoin pour interpréter
        // l'attestation (l'App ID est haché dans son extension).
        let bundleId = Bundle.main.bundleIdentifier ?? "?"
        fixture["app"] = [
            "bundleId": bundleId,
            "environment": "development",  // build de développement, cf. journal C3
        ]
        fixture["device"] = [
            "model": UIDevice.current.model,
            "systemName": UIDevice.current.systemName,
            "systemVersion": UIDevice.current.systemVersion,
        ]
        ok("bundle \(bundleId) — iOS \(UIDevice.current.systemVersion)")

        // ── Clé d'enveloppe (moitié Secure Enclave de C3) ──────────────────
        do {
            SigningKey.delete(tag: signingTag)
            var key: SigningKey!
            let creation = try timed { key = try SigningKey.create(tag: signingTag) }
            let kid = try key.kid()
            let pub = try key.publicKeyX962()
            ok("clé d'enveloppe créée — enclave: \(key.secureEnclave), \(fmt(creation))")
            ok("kid \(kid.base64EncodedString())")

            // Signature de contrôle : on vérifie le format r‖s, pas la validité.
            var signature = Data()
            let signing = try timed { signature = try key.signRaw(Data("sonde".utf8)) }
            ok("signature brute \(signature.count) octets, \(fmt(signing))")

            fixture["signingKey"] = [
                "kid": kid.base64EncodedString(),
                "publicKeyX962": pub.base64EncodedString(),
                "secureEnclave": key.secureEnclave,
                "creation_ms": creation,
                "signature_ms": signing,
            ]
        } catch {
            ko("clé d'enveloppe : \(describe(error))")
        }

        // ── App Attest ────────────────────────────────────────────────────
        guard AppAttest.isSupported else {
            ko("App Attest indisponible sur cet appareil")
            return (lines, serialize(fixture))
        }
        ok("App Attest supporté")

        var keyId = ""
        do {
            let d = try await timedAsync { keyId = try await AppAttest.generateKey() }
            ok("keyId \(keyId) — \(fmt(d))")
            fixture["keyId"] = keyId
            fixture["keyId_ms"] = d
        } catch {
            ko("generateKey : \(describe(error))")
            return (lines, serialize(fixture))
        }

        // Enrôlement : le défi vient du serveur dans la boucle réelle. Ici un
        // défi fixe et publié dans le vecteur, pour que la phase D puisse
        // recalculer le clientDataHash et vérifier la liaison.
        do {
            let challenge = Data("probative/spike-c3/enrollment-challenge".utf8)
            let hash = Data(SHA256.hash(data: challenge))
            var attestation = Data()
            let d = try await timedAsync {
                attestation = try await AppAttest.attest(keyId: keyId, clientDataHash: hash)
            }
            ok("attestation \(attestation.count) octets — \(fmt(d))")
            fixture["enrollment"] = [
                "challenge": challenge.base64EncodedString(),
                "clientDataHash": hash.base64EncodedString(),
                "attestation": attestation.base64EncodedString(),
                "elapsed_ms": d,
            ]
        } catch {
            ko("attestKey : \(describe(error))")
        }

        // ── Assertion liée à R1 (avance sur C5) ───────────────────────────
        // R1 = SHA-256(payload_bytes ‖ nonce), sans exception (invariant 2).
        // Les deux composants partent dans le vecteur : sans eux le
        // vérificateur ne peut pas refaire le calcul, et un test qui ne
        // recalcule pas R1 ne teste pas R1.
        do {
            let payload = Data("charge utile de substitution — vecteur C3".utf8)
            let nonce = Data((0..<16).map { UInt8($0 &* 7 &+ 3) })
            let r1 = Data(SHA256.hash(data: payload + nonce))
            var assertion = Data()
            let d = try await timedAsync {
                assertion = try await AppAttest.generateAssertion(keyId: keyId, clientDataHash: r1)
            }
            ok("assertion \(assertion.count) octets — \(fmt(d))")
            fixture["assertion"] = [
                "payload": payload.base64EncodedString(),
                "nonce": nonce.base64EncodedString(),
                "clientDataHash": r1.base64EncodedString(),
                "assertion": assertion.base64EncodedString(),
                "elapsed_ms": d,
            ]
        } catch {
            ko("generateAssertion : \(describe(error))")
        }

        return (lines, serialize(fixture))
    }

    /// Écrit le vecteur dans le conteneur de l'application, d'où `devicectl`
    /// sait le rapatrier.
    static func write(_ fixture: Data) -> URL? {
        guard
            let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        else { return nil }
        let url = dir.appendingPathComponent("c3-fixture.json")
        do {
            try fixture.write(to: url)
            print("[probe] vecteur écrit : \(url.path)")
            return url
        } catch {
            print("[probe] ECHEC écriture du vecteur : \(error)")
            return nil
        }
    }

    private static func serialize(_ o: [String: Any]) -> Data? {
        try? JSONSerialization.data(withJSONObject: o, options: [.prettyPrinted, .sortedKeys])
    }

    // Chronométrage en millisecondes. `DispatchTime` plutôt que
    // `ContinuousClock`, disponible dès iOS 15 comme le cœur.
    private static func timed(_ work: () throws -> Void) rethrows -> Double {
        let start = DispatchTime.now().uptimeNanoseconds
        try work()
        return Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }

    private static func timedAsync(_ work: () async throws -> Void) async rethrows -> Double {
        let start = DispatchTime.now().uptimeNanoseconds
        try await work()
        return Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }

    private static func fmt(_ ms: Double) -> String {
        String(format: "%.1f ms", ms)
    }

    /// Les erreurs DeviceCheck sortent en `NSError` peu bavard ; le domaine et
    /// le code sont ce qui permet de distinguer « App ID non provisionné » de
    /// « pas de réseau ».
    private static func describe(_ error: Error) -> String {
        let e = error as NSError
        return "\(e.domain) code \(e.code) — \(e.localizedDescription)"
    }
}
