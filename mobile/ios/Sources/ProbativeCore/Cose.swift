import Foundation

public enum CoseError: Error, Equatable {
    case malformedDer(String)
}

/// Assemblage `COSE_Sign1` du format `probative/0.1` (spec §2, ADR-0001).
///
/// Uniquement de la construction d'octets : aucune décision, aucun accès
/// à la Secure Enclave ici. La signature est fournie par l'appelant —
/// c'est ce qui rend chaque étape comparable aux vecteurs d'or.
public enum Cose {

    private static let spec = "probative/0.1"

    /// En-tête protégé encodé : alg ES256, kid, version de spec, déploiement,
    /// profil.
    ///
    /// Le profil (label 102, spec §2.5, ADR-0005) est ici et non dans la
    /// charge utile : le retirer ou le changer invalide la signature. Sa
    /// valeur est celle rendue par la route `/nonce` du serveur — la
    /// déclarer de son propre chef fait rejeter l'enveloppe.
    public static func protectedHeader(
        kid: Data,
        deployment: String,
        profile: String
    ) -> Data {
        Cbor.encode(.map([
            1: .int(-7),
            4: .bytes(kid),
            100: .text(spec),
            101: .text(deployment),
            102: .text(profile),
        ]))
    }

    /// `Sig_structure` (RFC 8152 §4.4) — les octets réellement signés.
    /// Contexte "Signature1", `external_aad` vide, en-tête protégé et
    /// charge utile en chaînes d'octets, jamais re-décodés.
    public static func sigStructure(protected: Data, payload: Data) -> Data {
        Cbor.encode(.array([
            .text("Signature1"),
            .bytes(protected),
            .bytes(Data()),
            .bytes(payload),
        ]))
    }

    /// Enveloppe complète : `COSE_Sign1` étiqueté (tag 18). L'en-tête non
    /// protégé ne contient que la preuve de fraîcheur (label 200), qui se
    /// lie au contenu par la règle R1 — pas par la signature.
    public static func envelope(
        protected: Data,
        freshness: [Int64: CborValue],
        payload: Data,
        signature: Data
    ) -> Data {
        precondition(signature.count == 64, "signature r‖s de 64 octets attendue")
        return Cbor.encode(.tag(18, .array([
            .bytes(protected),
            .map([200: .map(freshness)]),
            .bytes(payload),
            .bytes(signature),
        ])))
    }

    /// Convertit une signature ECDSA DER — ce que rend `SecKeyCreateSignature`
    /// — vers la forme brute `r‖s` de COSE : deux entiers non signés cadrés
    /// à 32 octets.
    public static func rawSignature(fromDer der: Data) throws -> Data {
        var reader = DerReader([UInt8](der))
        try reader.expect(0x30)
        _ = try reader.readLength()
        let r = try reader.readInteger()
        let s = try reader.readInteger()
        guard reader.exhausted else {
            throw CoseError.malformedDer("octets résiduels après la séquence")
        }
        return try leftPadded(r) + leftPadded(s)
    }

    private static func leftPadded(_ unsigned: [UInt8]) throws -> Data {
        guard unsigned.count <= 32 else {
            throw CoseError.malformedDer("entier de plus de 32 octets : pas du P-256")
        }
        return Data(repeating: 0, count: 32 - unsigned.count) + Data(unsigned)
    }

    /// Lecteur DER minimal : juste ce qu'exige ECDSA-Sig-Value.
    private struct DerReader {
        private let data: [UInt8]
        private var pos = 0

        init(_ data: [UInt8]) { self.data = data }

        var exhausted: Bool { pos == data.count }

        mutating func expect(_ tag: UInt8) throws {
            guard pos < data.count, data[pos] == tag else {
                throw CoseError.malformedDer("octet \(tag) attendu à la position \(pos)")
            }
            pos += 1
        }

        mutating func readLength() throws -> Int {
            guard pos < data.count else { throw CoseError.malformedDer("longueur tronquée") }
            let first = Int(data[pos])
            pos += 1
            if first < 0x80 { return first }
            // Une signature P-256 tient toujours sur une longueur d'un octet.
            guard first == 0x81, pos < data.count else {
                throw CoseError.malformedDer("longueur inattendue pour du P-256")
            }
            let length = Int(data[pos])
            pos += 1
            return length
        }

        mutating func readInteger() throws -> [UInt8] {
            try expect(0x02)
            let length = try readLength()
            guard length >= 1, length <= 33, pos + length <= data.count else {
                throw CoseError.malformedDer("entier de taille invalide : \(length)")
            }
            var start = pos
            var remaining = length
            // Le zéro de tête n'existe que pour neutraliser un bit de signe.
            while remaining > 1, data[start] == 0 {
                start += 1
                remaining -= 1
            }
            let value = Array(data[start ..< start + remaining])
            pos += length
            return value
        }
    }
}
