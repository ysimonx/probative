import DeviceCheck
import Foundation

/// Enveloppe mince de `DCAppAttestService` — la preuve de fraîcheur iOS.
///
/// L'enrôlement transmet l'objet d'attestation (`attest`), la capture
/// une assertion dont le `clientDataHash` vaut exactement le défi R1 :
/// `SHA-256(payload_bytes ‖ nonce)`. Aucune décision ici : les octets
/// partent opaques au serveur, qui les valide en phase D.
///
/// Indisponible hors appareil réel (simulateur, macOS) : les appels
/// échouent, `isSupported` le dit à l'avance.
public enum AppAttest {

    public static var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    /// Génère la paire App Attest ; le `keyId` retourné est à conserver
    /// et à transmettre à l'enrôlement.
    public static func generateKey() async throws -> String {
        try await DCAppAttestService.shared.generateKey()
    }

    /// Objet d'attestation initial, lié au défi d'enrôlement du serveur.
    public static func attest(keyId: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
    }

    /// Assertion de capture — `clientDataHash` est le défi R1, jamais
    /// autre chose (règle R1, non négociable).
    public static func generateAssertion(keyId: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
}
