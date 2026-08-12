import CryptoKit
import XCTest

@testable import ProbativeCore

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
        // …/mobile/ios/Tests/ProbativeCoreTests/Ce fichier → racine.
        for _ in 0 ..< 5 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("verifier-python/tests/vectors")
    }()

    private func vector(_ name: String) throws -> Data {
        try Data(contentsOf: Self.vectorsDir.appendingPathComponent(name))
    }

    /// Les quatre jeux de vecteurs. `core` n'est pas décoratif : c'est la
    /// seule forme sans position ni dimensions, et donc la seule qui
    /// vérifie que l'encodeur ne suppose pas une acquisition (ADR-0005).
    ///
    /// `core-ios` en est la variante de posture iOS, celle que ce cœur
    /// produit réellement — voir ``CorePayloadVectorTests``, qui l'épingle
    /// au code d'appareil et non au seul encodeur.
    private static let vectorSets = ["android", "ios", "core", "core-ios"]

    private func inputs(_ name: String) throws -> [String: Any] {
        let manifest = try JSONSerialization.jsonObject(
            with: vector("manifest.json")
        ) as? [String: Any]
        return try XCTUnwrap(manifest?[name] as? [String: Any])
    }

    private func hexData(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            UInt8(s.dropFirst($0).prefix(2), radix: 16)!
        })
    }

    /// Miroir de `factory.make_payload`, valeurs par défaut comprises.
    private func payload(inputs: [String: Any]) throws -> CborValue {
        let platform = try XCTUnwrap(inputs["platform"] as? String)
        let capture = try XCTUnwrap(inputs["profile"] as? String) == "capture"

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
        var media: [Int64: CborValue] = [
            1: "sha-256",
            2: .bytes(hexData(try XCTUnwrap(inputs["media_digest_hex"] as? String))),
            3: .text(capture ? "image/jpeg" : "application/pdf"),
            4: 1_842_301,
            6: 85,
        ]
        var payload: [Int64: CborValue] = [
            1: .bytes(hexData(try XCTUnwrap(inputs["nonce_hex"] as? String))),
            4: .map([1: .int(wallMs), 2: 4_312_004, 3: 120, 4: true]),
            5: .map(posture),
        ]

        // Le noyau ne décrit que des octets : ni dimensions, ni position,
        // ni corroboration — rien qui suppose un capteur ou un lieu.
        if capture {
            media[5] = [4032, 3024]
            payload[3] = .map(position)
            payload[6] = claims
        }
        payload[2] = .map(media)

        if let prev = inputs["prev_digest_hex"] as? String {
            payload[7] = .bytes(hexData(prev))
        }
        return .map(payload)
    }

    func testChargeUtileOctetAOctet() throws {
        for name in Self.vectorSets {
            let inputs = try inputs(name)
            XCTAssertEqual(
                try vector("\(name).payload.cbor"),
                Cbor.encode(try payload(inputs: inputs)),
                name
            )
        }
    }

    func testEnTeteProtegeOctetAOctet() throws {
        for name in Self.vectorSets {
            let inputs = try inputs(name)
            let kid = hexData(try XCTUnwrap(inputs["kid_hex"] as? String))
            XCTAssertEqual(
                try vector("\(name).protected.cbor"),
                Cose.protectedHeader(
                    kid: kid,
                    deployment: "test-deployment",
                    profile: try XCTUnwrap(inputs["profile"] as? String)
                ),
                name
            )
        }
    }

    func testSigStructureOctetAOctet() throws {
        for name in Self.vectorSets {
            XCTAssertEqual(
                try vector("\(name).sig_structure.cbor"),
                Cose.sigStructure(
                    protected: try vector("\(name).protected.cbor"),
                    payload: try vector("\(name).payload.cbor")
                ),
                name
            )
        }
    }

    func testDefiR1SurLesOctetsEncodes() throws {
        for name in Self.vectorSets {
            let nonce = hexData(try XCTUnwrap(try inputs(name)["nonce_hex"] as? String))
            let payloadBytes = try vector("\(name).payload.cbor")
            let challenge = Data(SHA256.hash(data: payloadBytes + nonce))
            XCTAssertEqual(try vector("\(name).challenge.bin"), challenge, name)
        }
    }

    func testAssemblageDEnveloppeOctetAOctet() throws {
        // La signature des vecteurs est ECDSA déterministe, irréproductible
        // avec une clé matérielle : on la prélève de l'enveloppe (les 64
        // derniers octets) et on vérifie que tout le reste s'assemble à
        // l'identique autour d'elle.
        for name in Self.vectorSets {
            let inputs = try inputs(name)
            let envelope = try vector("\(name).envelope.prbv")
            let signature = Data(envelope.suffix(64))

            let token = Data("NULLTOKEN:".utf8) + (try vector("\(name).challenge.bin"))
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
                    protected: try vector("\(name).protected.cbor"),
                    freshness: freshness,
                    payload: try vector("\(name).payload.cbor"),
                    signature: signature
                ),
                name
            )
        }
    }
}
