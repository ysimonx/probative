import CryptoKit
import Foundation
import Security

public enum SigningKeyError: Error {
    case creation(String)
    case notFound
    case export(String)
    case signing(String)
}

/// Clé de signature d'enveloppe : P-256, Secure Enclave quand elle est
/// disponible, persistée dans le trousseau sous une étiquette.
///
/// Même convention d'identifiant que le cœur Android et la fabrique de
/// référence : `kid` = SHA-256 du point public non compressé
/// (`04 ‖ X ‖ Y`, 65 octets) — c'est lui qui lie la signature à la clé
/// enrôlée (règle R2). iOS n'a pas d'équivalent de la chaîne
/// d'attestation de clé Android : la preuve de résidence matérielle
/// passe par App Attest, qui atteste l'application (phase D).
public struct SigningKey {

    public let secKey: SecKey
    public let secureEnclave: Bool

    /// Crée une clé, Secure Enclave d'abord, repli logiciel explicite.
    /// `permanent: false` sert aux tests : rien n'entre au trousseau.
    public static func create(
        tag: Data,
        secureEnclave: Bool = true,
        permanent: Bool = true
    ) throws -> SigningKey {
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: permanent,
            kSecAttrApplicationTag as String: tag,
        ]
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        if secureEnclave {
            attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            var accessError: Unmanaged<CFError>?
            // Clé utilisable dès que l'appareil est déverrouillé, sans
            // biométrie : la signature part en arrière-plan juste après
            // la capture, la latence media.6 ne doit rien attendre.
            guard
                let access = SecAccessControlCreateWithFlags(
                    nil,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    .privateKeyUsage,
                    &accessError
                )
            else {
                throw SigningKeyError.creation(describe(accessError))
            }
            privateAttrs[kSecAttrAccessControl as String] = access
        }
        attrs[kSecPrivateKeyAttrs as String] = privateAttrs

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw SigningKeyError.creation(describe(error))
        }
        return SigningKey(secKey: key, secureEnclave: secureEnclave)
    }

    /// Recharge la clé persistée sous cette étiquette.
    public static func load(tag: Data) throws -> SigningKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            // Seule la clé privée est persistée, mais le filtre explicite
            // évite qu'un élément public homonyme réponde à sa place.
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
            throw SigningKeyError.notFound
        }
        let key = item as! SecKey
        let attrs = SecKeyCopyAttributes(key) as? [String: Any]
        let token = attrs?[kSecAttrTokenID as String] as? String
        return SigningKey(
            secKey: key,
            secureEnclave: token == (kSecAttrTokenIDSecureEnclave as String)
        )
    }

    public static func delete(tag: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Point public X9.62 non compressé — la représentation externe des
    /// clés EC de Security est déjà exactement `04 ‖ X ‖ Y`.
    public func publicKeyX962() throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(secKey) else {
            throw SigningKeyError.export("clé publique introuvable")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw SigningKeyError.export(describe(error))
        }
        guard data.count == 65, data.first == 0x04 else {
            throw SigningKeyError.export("représentation inattendue : \(data.count) octets")
        }
        return data
    }

    public func kid() throws -> Data {
        Data(SHA256.hash(data: try publicKeyX962()))
    }

    /// Signe et rend la signature brute `r‖s` attendue par COSE.
    public func signRaw(_ message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let der = SecKeyCreateSignature(
                secKey,
                .ecdsaSignatureMessageX962SHA256,
                message as CFData,
                &error
            ) as Data?
        else {
            throw SigningKeyError.signing(describe(error))
        }
        return try Cose.rawSignature(fromDer: der)
    }
}

private func describe(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else { return "erreur Security inconnue" }
    return String(describing: error)
}
