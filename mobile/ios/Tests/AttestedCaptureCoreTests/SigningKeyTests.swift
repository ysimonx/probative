import CryptoKit
import XCTest

@testable import AttestedCaptureCore

/// Étape C3. Le chemin logiciel se valide entièrement sur l'hôte :
/// export X9.62, convention `kid`, signature vérifiée par CryptoKit.
/// Le chemin Secure Enclave est conditionnel — il passe sur appareil
/// réel (et sur les Mac Apple Silicon quand l'environnement de test a
/// accès à l'enclave), sinon il se saute en le disant.
final class SigningKeyTests: XCTestCase {

    private let tag = Data("dev.attestedcapture.test.signing".utf8)

    override func tearDown() {
        SigningKey.delete(tag: tag)
        super.tearDown()
    }

    private func hexData(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            UInt8(s.dropFirst($0).prefix(2), radix: 16)!
        })
    }

    func testExportKidEtSignatureSurCleLogicielle() throws {
        let key = try SigningKey.create(tag: tag, secureEnclave: false, permanent: false)

        let x962 = try key.publicKeyX962()
        XCTAssertEqual(x962.count, 65)
        XCTAssertEqual(x962.first, 0x04)
        XCTAssertEqual(try key.kid(), Data(SHA256.hash(data: x962)))

        // La signature brute doit convaincre une pile indépendante.
        let message = Data("octets a signer".utf8)
        let raw = try key.signRaw(message)
        XCTAssertEqual(raw.count, 64)
        let verifier = try P256.Signing.PublicKey(x963Representation: x962)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        XCTAssertTrue(verifier.isValidSignature(signature, for: message))
    }

    func testConventionKidIdentiqueAuManifest() throws {
        // Même couple (clé publique, kid) de référence que le test JVM
        // Android : les trois implémentations doivent converger.
        let manifest = try JSONSerialization.jsonObject(
            with: Data(
                contentsOf: {
                    var url = URL(fileURLWithPath: #filePath)
                    for _ in 0 ..< 5 { url.deleteLastPathComponent() }
                    return url.appendingPathComponent(
                        "verifier-python/tests/vectors/manifest.json"
                    )
                }()
            )
        ) as? [String: Any]

        for platform in ["android", "ios"] {
            let inputs = try XCTUnwrap(manifest?[platform] as? [String: Any])
            let x962 = hexData(try XCTUnwrap(inputs["public_key_x962_hex"] as? String))
            let kid = hexData(try XCTUnwrap(inputs["kid_hex"] as? String))
            XCTAssertEqual(Data(SHA256.hash(data: x962)), kid, platform)

            // L'aller-retour par Security doit être exact : la clé parsée
            // se réexporte octet à octet.
            var error: Unmanaged<CFError>?
            let attrs: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            ]
            let parsed = try XCTUnwrap(
                SecKeyCreateWithData(x962 as CFData, attrs as CFDictionary, &error)
            )
            let reencoded = try XCTUnwrap(
                SecKeyCopyExternalRepresentation(parsed, &error) as Data?
            )
            XCTAssertEqual(reencoded, x962, platform)
        }
    }

    func testPersistanceParEtiquette() throws {
        // C4 rechargera la clé par étiquette à chaque capture : ce
        // chemin ne doit pas rester non testé jusqu'au jour de l'appareil.
        let created: SigningKey
        do {
            created = try SigningKey.create(tag: tag, secureEnclave: false, permanent: true)
        } catch {
            throw XCTSkip("trousseau inaccessible dans cet environnement : \(error)")
        }

        let loaded = try SigningKey.load(tag: tag)
        XCTAssertEqual(try loaded.publicKeyX962(), try created.publicKeyX962())
        XCTAssertFalse(loaded.secureEnclave)

        SigningKey.delete(tag: tag)
        XCTAssertThrowsError(try SigningKey.load(tag: tag))
    }

    func testCleSecureEnclaveSiDisponible() throws {
        let key: SigningKey
        do {
            key = try SigningKey.create(tag: tag, secureEnclave: true, permanent: false)
        } catch {
            throw XCTSkip("Secure Enclave indisponible dans cet environnement : \(error)")
        }

        XCTAssertTrue(key.secureEnclave)
        let x962 = try key.publicKeyX962()
        XCTAssertEqual(x962.count, 65)

        let message = Data("octets a signer dans l'enclave".utf8)
        let raw = try key.signRaw(message)
        let verifier = try P256.Signing.PublicKey(x963Representation: x962)
        XCTAssertTrue(
            verifier.isValidSignature(
                try P256.Signing.ECDSASignature(rawRepresentation: raw),
                for: message
            )
        )
    }
}
