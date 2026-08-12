import XCTest

@testable import ProbativeCore

/// Le vecteur `core-ios` reproduit **par le code qui tourne sur l'appareil**.
///
/// Distinct de ``GoldenVectorsTests``, et la nuance est tout l'intérêt : là-bas
/// la charge utile est bâtie à la main dans le test, ce qui éprouve l'encodeur
/// CBOR. Ici, elle passe par ``CorePayload/build(nonce:media:timing:posture:previousDigest:)``,
/// celui-là même qu'appelle ``Sealer`` — un décalage entre la structure
/// produite sur appareil et `factory.make_payload` échoue donc sur l'hôte,
/// avant d'aller chercher un iPhone et de lire un `SIGNATURE_INVALID` sans
/// cause visible.
///
/// Seule la collecte reste hors de portée d'un test d'hôte : les valeurs sont
/// ici celles du vecteur, comme si l'appareil les avait mesurées.
final class CorePayloadVectorTests: XCTestCase {

    private static let vectorsDir: URL = {
        var url = URL(fileURLWithPath: #filePath)
        // …/mobile/ios/Tests/ProbativeCoreTests/Ce fichier → racine.
        for _ in 0 ..< 5 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("verifier-python/tests/vectors")
    }()

    private func vector(_ name: String) throws -> Data {
        try Data(contentsOf: Self.vectorsDir.appendingPathComponent(name))
    }

    private func hexData(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            UInt8(s.dropFirst($0).prefix(2), radix: 16)!
        })
    }

    private func inputs() throws -> [String: Any] {
        let manifest = try JSONSerialization.jsonObject(
            with: vector("manifest.json")
        ) as? [String: Any]
        return try XCTUnwrap(manifest?["core-ios"] as? [String: Any])
    }

    func testChargeUtileDuNoyauOctetAOctet() throws {
        let inputs = try inputs()

        let payload = CorePayload.build(
            nonce: hexData(try XCTUnwrap(inputs["nonce_hex"] as? String)),
            media: Media(
                digest: hexData(try XCTUnwrap(inputs["media_digest_hex"] as? String)),
                mimeType: "application/pdf",
                sizeBytes: 1_842_301,
                signLatencyMs: 85
            ),
            timing: Timing(
                wallMs: try XCTUnwrap(inputs["wall_ms"] as? Int64),
                uptimeMs: 4_312_004,
                utcOffsetMinutes: 120,
                automaticTime: true
            ),
            posture: Posture(
                platform: "ios",
                osVersion: "17.4",
                appVersion: "0.1.0",
                debuggerAttached: false,
                simulatorSuspected: false,
                jailbreakSuspected: false
            )
        )

        XCTAssertEqual(Cbor.encode(payload), try vector("core-ios.payload.cbor"))
    }

    /// Une mesure non faite s'omet, elle ne se simule pas. C'est ce que rend
    /// ``DeviceState`` pour les heuristiques de jailbreak hors appareil, et le
    /// serveur doit voir la différence entre « rien détecté » et « rien
    /// cherché ».
    func testLesChampsOptionnelsAbsentsNeSontPasEncodes() throws {
        let posture = Posture(
            platform: "ios",
            osVersion: "17.4",
            appVersion: "0.1.0",
            debuggerAttached: false,
            simulatorSuspected: false
        ).cbor

        guard case .map(let entries) = posture else {
            return XCTFail("posture attendue en map")
        }
        XCTAssertEqual(entries.keys.sorted(), [1, 2, 3, 4, 5])
    }

    /// `timing[4]` est **toujours** omis sur iOS : le système n'expose aucune
    /// interface publique disant si l'heure est réglée automatiquement. Le
    /// test fige cette asymétrie avec Android plutôt que de la laisser passer
    /// pour un oubli.
    func testLaSynchronisationAutomatiqueEstOmiseParLaCollecte() {
        XCTAssertNil(DeviceState.timing().automaticTime)
    }
}

/// Le vecteur `ios` — profil `capture` — reproduit **par le code d'appareil**.
///
/// Même rôle que ``CorePayloadVectorTests`` pour le noyau : c'est
/// ``CapturePayload/build(nonce:media:position:timing:posture:claims:previousDigest:)``
/// qui construit, celui-là même qu'appellera l'acquisition. Le vecteur `ios`
/// est le seul du jeu à porter les quatre réclamations et une position sans
/// nombre de satellites — donc le seul oracle du profil `capture` côté iOS.
final class CapturePayloadVectorTests: XCTestCase {

    private static let vectorsDir: URL = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 5 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("verifier-python/tests/vectors")
    }()

    private func vector(_ name: String) throws -> Data {
        try Data(contentsOf: Self.vectorsDir.appendingPathComponent(name))
    }

    private func hexData(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            UInt8(s.dropFirst($0).prefix(2), radix: 16)!
        })
    }

    func testChargeUtileDAcquisitionOctetAOctet() throws {
        let manifest = try JSONSerialization.jsonObject(with: vector("manifest.json"))
        let inputs = try XCTUnwrap((manifest as? [String: Any])?["ios"] as? [String: Any])

        let payload = CapturePayload.build(
            nonce: hexData(try XCTUnwrap(inputs["nonce_hex"] as? String)),
            media: Media(
                digest: hexData(try XCTUnwrap(inputs["media_digest_hex"] as? String)),
                mimeType: "image/jpeg",
                sizeBytes: 1_842_301,
                signLatencyMs: 85,
                pixelSize: (width: 4032, height: 3024)
            ),
            position: Position(
                latitude: 48.2973,
                longitude: 4.0744,
                horizontalAccuracy: 8.0,
                altitude: 112.0,
                verticalAccuracy: 4.0,
                provider: .gnss,
                fixAgeMs: 1_200
            ),
            timing: Timing(
                wallMs: try XCTUnwrap(inputs["wall_ms"] as? Int64),
                uptimeMs: 4_312_004,
                utcOffsetMinutes: 120,
                automaticTime: true
            ),
            posture: Posture(
                platform: "ios",
                osVersion: "17.4",
                appVersion: "0.1.0",
                debuggerAttached: false,
                simulatorSuspected: false,
                jailbreakSuspected: false
            ),
            claims: [
                Claim(type: "baro-alt", source: "barometer", uptimeMs: 4_210, value: .double(115.0)),
                Claim(type: "baro", source: "barometer", uptimeMs: 4_210, value: .double(999.4)),
                Claim(
                    type: "motion",
                    source: "accelerometer",
                    uptimeMs: 4_100,
                    value: .array([
                        .array([.int(0), .double(0.01), .double(0.02), .double(9.79)]),
                        .array([.int(500), .double(0.03), .double(0.01), .double(9.81)]),
                    ])
                ),
                Claim(type: "steps", source: "pedometer", uptimeMs: 4_180, value: .int(0)),
            ]
        )

        XCTAssertEqual(Cbor.encode(payload), try vector("ios.payload.cbor"))
    }
}
