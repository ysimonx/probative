import CryptoKit
import XCTest

@testable import AttestedCaptureCore

/// Le contrat du spike : reproduire octet à octet les vecteurs d'or du
/// vérificateur (`verifier-python/tests/vectors/`, source unique — le
/// fichier source sert d'ancre pour retrouver la racine du dépôt).
///
/// La construction de la charge utile reflète `factory.make_payload`,
/// l'implémentation de référence : si ce test ne peut pas reproduire un
/// vecteur, c'est ce code-ci qui s'écarte de la spécification.
final class GoldenVectorsTests: XCTestCase {

    private static let vectorsDir: URL = {
        var url = URL(fileURLWithPath: #filePath)
        // …/mobile/ios/Tests/AttestedCaptureCoreTests/Ce fichier → racine.
        for _ in 0 ..< 5 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("verifier-python/tests/vectors")
    }()

    private func vector(_ name: String) throws -> Data {
        try Data(contentsOf: Self.vectorsDir.appendingPathComponent(name))
    }

    private func inputs(_ platform: String) throws -> [String: Any] {
        let manifest = try JSONSerialization.jsonObject(
            with: vector("manifest.json")
        ) as? [String: Any]
        return try XCTUnwrap(manifest?[platform] as? [String: Any])
    }

    private func hexData(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            UInt8(s.dropFirst($0).prefix(2), radix: 16)!
        })
    }

    /// Miroir de `factory.make_payload`, valeurs par défaut comprises.
    private func payload(for platform: String, inputs: [String: Any]) throws -> CborValue {
        var position: [Int64: CborValue] = [
            1: 48.2973, 2: 4.0744, 3: 8.0, 4: 112.0, 5: 4.0, 6: "gnss", 7: 1200,
        ]
        var posture: [Int64: CborValue] = [
            1: .text(platform),
            2: .text(platform == "android" ? "14" : "17.4"),
            3: "0.1.0",
            4: false,
            5: false,
        ]
        if platform == "android" {
            position[8] = 11
            posture[6] = false
            posture[7] = false
            posture[8] = .array([])
        } else {
            posture[9] = false
        }

        let claims: CborValue = [
            [1: "baro-alt", 2: "barometer", 3: 4210, 4: 115.0],
            [1: "baro", 2: "barometer", 3: 4210, 4: 999.4],
            [
                1: "motion", 2: "accelerometer", 3: 4100,
                4: [[0, 0.01, 0.02, 9.79], [500, 0.03, 0.01, 9.81]],
            ],
            [1: "steps", 2: "pedometer", 3: 4180, 4: 0],
        ]

        let wallMs = try XCTUnwrap(inputs["wall_ms"] as? NSNumber).int64Value
        var payload: [Int64: CborValue] = [
            1: .bytes(hexData(try XCTUnwrap(inputs["nonce_hex"] as? String))),
            2: [
                1: "sha-256",
                2: .bytes(hexData(try XCTUnwrap(inputs["media_digest_hex"] as? String))),
                3: "image/jpeg",
                4: 1_842_301,
                5: [4032, 3024],
                6: 85,
            ],
            3: .map(position),
            4: .map([1: .int(wallMs), 2: 4_312_004, 3: 120, 4: true]),
            5: .map(posture),
            6: claims,
        ]
        if let prev = inputs["prev_digest_hex"] as? String {
            payload[7] = .bytes(hexData(prev))
        }
        return .map(payload)
    }

    func testChargeUtileOctetAOctet() throws {
        for platform in ["android", "ios"] {
            let inputs = try inputs(platform)
            XCTAssertEqual(
                try vector("\(platform).payload.cbor"),
                Cbor.encode(try payload(for: platform, inputs: inputs)),
                platform
            )
        }
    }

    func testEnTeteProtegeOctetAOctet() throws {
        for platform in ["android", "ios"] {
            let kid = hexData(try XCTUnwrap(try inputs(platform)["kid_hex"] as? String))
            XCTAssertEqual(
                try vector("\(platform).protected.cbor"),
                Cose.protectedHeader(kid: kid, deployment: "test-deployment"),
                platform
            )
        }
    }

    func testSigStructureOctetAOctet() throws {
        for platform in ["android", "ios"] {
            XCTAssertEqual(
                try vector("\(platform).sig_structure.cbor"),
                Cose.sigStructure(
                    protected: try vector("\(platform).protected.cbor"),
                    payload: try vector("\(platform).payload.cbor")
                ),
                platform
            )
        }
    }

    func testDefiR1SurLesOctetsEncodes() throws {
        for platform in ["android", "ios"] {
            let nonce = hexData(try XCTUnwrap(try inputs(platform)["nonce_hex"] as? String))
            let payloadBytes = try vector("\(platform).payload.cbor")
            let challenge = Data(SHA256.hash(data: payloadBytes + nonce))
            XCTAssertEqual(try vector("\(platform).challenge.bin"), challenge, platform)
        }
    }

    func testAssemblageDEnveloppeOctetAOctet() throws {
        // La signature des vecteurs est ECDSA déterministe, irréproductible
        // avec une clé matérielle : on la prélève de l'enveloppe (les 64
        // derniers octets) et on vérifie que tout le reste s'assemble à
        // l'identique autour d'elle.
        for platform in ["android", "ios"] {
            let inputs = try inputs(platform)
            let envelope = try vector("\(platform).envelope.acap")
            let signature = Data(envelope.suffix(64))

            let token = Data("NULLTOKEN:".utf8) + (try vector("\(platform).challenge.bin"))
            var freshness: [Int64: CborValue] = [
                1: .text(try XCTUnwrap(inputs["freshness_kind"] as? String)),
                2: .bytes(token),
            ]
            if let counter = inputs["assertion_counter"] as? NSNumber, !(counter is NSNull) {
                freshness[3] = .int(counter.int64Value)
            }

            XCTAssertEqual(
                envelope,
                Cose.envelope(
                    protected: try vector("\(platform).protected.cbor"),
                    freshness: freshness,
                    payload: try vector("\(platform).payload.cbor"),
                    signature: signature
                ),
                platform
            )
        }
    }
}
