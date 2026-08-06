import CryptoKit
import XCTest

@testable import AttestedCaptureCore

/// Conversion DER → `r‖s`. `SecKeyCreateSignature` rend du DER ; COSE
/// exige la forme brute. CryptoKit expose les deux représentations d'une
/// même signature : la conversion doit tomber exactement sur la sienne.
final class DerSignatureTests: XCTestCase {

    func testConversionCroiseeAvecCryptoKit() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("octets a signer".utf8)

        // Plusieurs signatures : r et s changent de taille DER selon leurs
        // zéros de tête, c'est ce que la conversion doit absorber.
        for _ in 0 ..< 32 {
            let signature = try key.signature(for: message)
            let raw = try Cose.rawSignature(fromDer: signature.derRepresentation)
            XCTAssertEqual(raw, signature.rawRepresentation)
        }
    }

    func testCadrageDesPetitsEntiersEtDesZerosDeTete() throws {
        // r = 1 (1 octet), s = valeur à bit de poids fort levé, précédée du
        // zéro DER qui neutralise le bit de signe.
        var s = [UInt8](repeating: 0xAB, count: 32)
        s[0] = 0x80
        let der = Data([0x30, 38, 0x02, 1, 1, 0x02, 33, 0] + s)

        let raw = try Cose.rawSignature(fromDer: der)

        XCTAssertEqual(raw.prefix(32), Data([UInt8](repeating: 0, count: 31) + [1]))
        XCTAssertEqual(raw.suffix(32), Data(s))
    }

    func testDerResidueRejete() {
        XCTAssertThrowsError(
            try Cose.rawSignature(fromDer: Data([0x30, 6, 0x02, 1, 1, 0x02, 1, 2, 0xFF]))
        )
    }
}
