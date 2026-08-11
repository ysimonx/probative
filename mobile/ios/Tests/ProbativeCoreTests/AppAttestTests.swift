import CryptoKit
import XCTest

@testable import ProbativeCore

/// Étape C3, moitié App Attest — exécutable sur appareil réel avec un
/// App ID provisionné uniquement. Hors appareil, le test constate
/// l'indisponibilité et se saute en le disant : le chemin compilé est
/// exactement celui que l'application de démonstration empruntera.
final class AppAttestTests: XCTestCase {

    func testGenerationEtAttestationSiSupporte() async throws {
        guard AppAttest.isSupported else {
            throw XCTSkip("App Attest non supporté ici (simulateur ou macOS)")
        }

        let keyId = try await AppAttest.generateKey()
        XCTAssertFalse(keyId.isEmpty)

        // Défi d'enrôlement factice — sur la boucle réelle, il vient du
        // serveur de dev et la validation est la phase D.
        let challenge = Data(SHA256.hash(data: Data("defi d'enrolement".utf8)))
        let attestation = try await AppAttest.attest(keyId: keyId, clientDataHash: challenge)
        XCTAssertFalse(attestation.isEmpty)
    }
}
