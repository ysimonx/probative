import CryptoKit
import Foundation

/// Source de preuve de fraîcheur — ce qui remplit le label 200 de l'en-tête
/// non protégé.
///
/// L'assemblage d'enveloppe ne connaît que ce protocole : il ne doit dépendre
/// ni d'App Attest, ni de ce qui viendra. C'est aussi ce qui permet à un test
/// d'exercer le chemin complet sans appareil réel, App Attest étant
/// indisponible sur l'hôte.
///
/// Le jeton est **opaque** : rien ici ne le lit, ne le décode et n'en déduit
/// un booléen de confiance (invariant 1).
public protocol FreshnessSource {

    /// Valeur du label 1 de `freshness` — `"app-attest"` ou `"play-integrity"`.
    var kind: String { get }

    /// Preuve liée au défi R1, qui vaut exactement `SHA-256(payload ‖ nonce)`.
    ///
    /// L'implémentation ne doit **jamais** demander une assertion sur autre
    /// chose : sans cette liaison, la preuve atteste seulement qu'un appareil
    /// sain existe quelque part (invariant 2).
    func token(challenge: Data) async throws -> Data
}

/// Fraîcheur iOS : une assertion App Attest dont le `clientDataHash` porte le
/// défi R1.
///
/// Point qui bloque net si on le manque : **deux clés distinctes vivent dans
/// l'appareil**. La clé de signature du format (Secure Enclave, désignée par
/// le `kid`) et la clé App Attest, gérée par `DCAppAttestService`, incapable
/// de signer autre chose qu'une assertion. `keyId` désigne la seconde.
public struct AppAttestFreshness: FreshnessSource {

    public static let kindName = "app-attest"

    private let keyId: String

    public init(keyId: String) {
        self.keyId = keyId
    }

    public var kind: String { Self.kindName }

    public func token(challenge: Data) async throws -> Data {
        try await AppAttest.generateAssertion(keyId: keyId, clientDataHash: challenge)
    }
}

/// Ce que rend un scellement. L'appelant n'a besoin que de `bytes` ; le reste
/// existe pour le diagnostic et pour les sondes, qui doivent pouvoir montrer
/// le défi qu'elles ont soumis sans le recalculer à leur façon — recalculer
/// est justement ce qui laisse les deux côtés diverger en silence.
public struct SealedEnvelope {
    public let bytes: Data
    public let payloadBytes: Data
    public let challenge: Data
    public let mediaDigest: Data
}

/// Scellement d'octets **remis** — le second point d'entrée du cœur, à côté de
/// l'acquisition (spec §2.5, « contenu acquis, contenu fourni »).
///
/// Un intégrateur qui possède déjà son écran photo passe par ici. Ce n'est pas
/// un mode dégradé mais une preuve **plus étroite** : ni position, ni
/// dimensions, ni plafond de recapture, parce que le cœur n'a pas observé
/// l'acquisition et n'affirme donc rien du monde physique. L'enveloppe dit
/// exactement ce qu'elle sait — *cet appareil, dans cet état, a signé ces
/// octets-là à cet instant, sous une clé matérielle attestée*.
///
/// Le profil produit est toujours `core`. Le nonce doit avoir été émis pour ce
/// profil : le serveur rejette une enveloppe dont le profil signé diffère de
/// celui du nonce, et il a raison de le faire.
///
/// Aucune décision de validité n'est prise ici (invariant 1) : le cœur
/// collecte, assemble, signe, et le serveur juge. Pendant Swift de
/// `core/envelope/Sealer.kt`.
public struct Sealer {

    private let deployment: String
    private let signingKey: SigningKey
    private let appVersion: String
    private let freshness: FreshnessSource

    public init(
        deployment: String,
        signingKey: SigningKey,
        appVersion: String,
        freshness: FreshnessSource
    ) {
        self.deployment = deployment
        self.signingKey = signingKey
        self.appVersion = appVersion
        self.freshness = freshness
    }

    /// Scelle `content` sous le nonce du serveur et rend l'enveloppe encodée.
    ///
    /// `acquiredAtUptime` est l'instant d'origine sur l'horloge monotone, qui
    /// sert à mesurer `media[6]`. Il vaut par défaut l'entrée dans cette
    /// méthode — la seule chose honnête pour des octets remis, dont le cœur
    /// ignore l'âge. L'acquisition (C4.2) passera l'instant de l'obturateur,
    /// et c'est là seulement que le champ discrimine une injection.
    ///
    /// `previousDigest` chaîne l'enveloppe à la précédente (spec §9).
    public func seal(
        content: Data,
        mimeType: String,
        nonce: Data,
        acquiredAtUptime: TimeInterval = ProcessInfo.processInfo.systemUptime,
        previousDigest: Data? = nil
    ) async throws -> SealedEnvelope {
        let mediaDigest = Data(SHA256.hash(data: content))
        let timing = DeviceState.timing()
        let posture = DeviceState.posture(appVersion: appVersion)

        // `media[6]` s'arrête à l'encodage de la charge utile, et pas à la
        // signature : le champ est *dans* ce qui est encodé, donc il ne peut
        // pas mesurer ce qui vient après lui. Ce qui reste dehors est
        // l'assertion et la signature — 18 ms et quelques millisecondes sur
        // iPhone 16, donc une constante, là où le discriminant recherché est
        // le temps passé *avant*.
        let elapsed = ProcessInfo.processInfo.systemUptime - acquiredAtUptime
        precondition(elapsed >= 0, "instant d'acquisition postérieur au scellement")

        let payload = CorePayload.build(
            nonce: nonce,
            media: Media(
                digest: mediaDigest,
                mimeType: mimeType,
                sizeBytes: content.count,
                signLatencyMs: Int((elapsed * 1000).rounded())
            ),
            timing: timing,
            posture: posture,
            previousDigest: previousDigest
        )
        return try await assemble(
            payload: payload,
            nonce: nonce,
            profile: CorePayload.profile,
            mediaDigest: mediaDigest
        )
    }

    /// Encode, lie par R1, obtient la fraîcheur, signe, assemble.
    ///
    /// Partagé par les deux points d'entrée : c'est **exactement** la part
    /// qui ne doit pas différer entre un scellement d'octets remis et une
    /// acquisition. La dupliquer laisserait les deux chemins diverger sur
    /// R1, ce qui ne se verrait qu'à la vérification.
    func assemble(
        payload: CborValue,
        nonce: Data,
        profile: String,
        mediaDigest: Data
    ) async throws -> SealedEnvelope {
        let payloadBytes = Cbor.encode(payload)

        // Règle R1, non négociable : le défi vaut exactement
        // SHA-256(payload_bytes ‖ nonce), sur les octets encodés et jamais sur
        // un ré-encodage de la structure.
        let challenge = Data(SHA256.hash(data: payloadBytes + nonce))
        let token = try await freshness.token(challenge: challenge)

        let protectedBytes = Cose.protectedHeader(
            kid: try signingKey.kid(),
            deployment: deployment,
            profile: profile
        )
        let signature = try signingKey.signRaw(
            Cose.sigStructure(protected: protectedBytes, payload: payloadBytes)
        )

        // Le compteur d'assertion (label 3) est **omis**, et c'est le bon
        // choix. Celui de l'en-tête n'est signé par rien ; celui
        // d'`authenticatorData`, à l'intérieur de l'assertion, l'est. Le
        // serveur retient le second et rejette un désaccord entre les deux —
        // déclarer une valeur non signée n'apporte donc rien et ne peut que
        // nuire. `time` atteint quand même son grade A par le compteur signé,
        // là où Android doit le gagner par chaînage.
        return SealedEnvelope(
            bytes: Cose.envelope(
                protected: protectedBytes,
                freshness: [1: .text(freshness.kind), 2: .bytes(token)],
                payload: payloadBytes,
                signature: signature
            ),
            payloadBytes: payloadBytes,
            challenge: challenge,
            mediaDigest: mediaDigest
        )
    }
}

#if os(iOS)

extension Sealer {

    /// Acquiert une photo et la scelle — le **premier** point d'entrée du
    /// cœur (spec §2.5), celui où il pilote la caméra.
    ///
    /// Ce que l'acquisition ajoute au scellement d'octets remis n'est pas la
    /// preuve de l'origine capteur : sur un appareil compromis, une caméra
    /// virtuelle injecte des images dans le pipeline. Elle ajoute un chemin
    /// **court et mesurable** entre capteur et signature, donc une attaque
    /// plus coûteuse et un `media[6]` exploitable. Différence de degré, pas
    /// de nature — et c'est exactement pourquoi `origin` reste plafonné à B.
    ///
    /// Le nonce doit avoir été émis pour le profil `capture`.
    ///
    /// Lève si le point de position n'arrive pas dans le délai : le profil
    /// l'exige, et mieux vaut échouer ici que faire signer une enveloppe que
    /// le serveur rejettera comme malformée.
    public func capture(
        nonce: Data,
        locationTimeout: TimeInterval = 15,
        previousDigest: Data? = nil
    ) async throws -> SealedEnvelope {
        // Position et corroboration partent **avant** l'obturateur et courent
        // pendant l'acquisition. Les enchaîner après coûtait 4,2 s dans
        // `media[6]` sur iPhone 16, et faisait tomber `origin` à C pour
        // « latence anormale » : le champ censé discriminer une injection
        // n'accusait alors que l'ordonnancement du client.
        //
        // Les mesures encadrent donc la capture au lieu de la suivre, ce qui
        // est aussi la lecture juste du format — une corroboration décrit
        // l'instant de la prise, pas l'instant où le client a fini de la
        // collecter.
        async let fixTask = Sensors.location(timeout: locationTimeout)
        async let claimsTask = Sensors.claims()

        let image = try await Camera.capture()
        let claims = await claimsTask
        guard let fix = await fixTask else {
            throw CaptureError.noPosition
        }
        return try await seal(
            image: image,
            position: Sensors.position(from: fix, shutterDate: shutterDate(of: image)),
            claims: claims,
            nonce: nonce,
            previousDigest: previousDigest
        )
    }

    /// Scelle une image **acquise par le cœur**, avec ses mesures.
    ///
    /// Séparé de `capture` pour qu'une sonde puisse rapporter chaque étape
    /// sans réimplémenter l'assemblage — et non pour offrir un chemin où un
    /// appelant fournirait ses propres octets en profil `capture`. Ce
    /// chemin-là est `seal(content:…)`, et il produit `core`.
    public func seal(
        image: CapturedImage,
        position: Position,
        claims: [Claim],
        nonce: Data,
        previousDigest: Data? = nil
    ) async throws -> SealedEnvelope {
        let mediaDigest = Data(SHA256.hash(data: image.bytes))

        // L'origine est l'obturateur, pas l'entrée dans cette méthode : c'est
        // là seulement que `media[6]` discrimine une injection, en mesurant
        // le temps réellement passé entre capteur et charge utile.
        let elapsed = ProcessInfo.processInfo.systemUptime - image.shutterUptime
        precondition(elapsed >= 0, "obturateur postérieur au scellement")

        let payload = CapturePayload.build(
            nonce: nonce,
            media: Media(
                digest: mediaDigest,
                // Le type vient du format réellement encodé, jamais d'un
                // littéral posé ici : deux sources se seraient contredites en
                // silence, et l'enveloppe aurait porté un type faux mais signé
                // (ADR-0007 point 3).
                mimeType: image.format.mimeType,
                sizeBytes: image.bytes.count,
                signLatencyMs: Int((elapsed * 1000).rounded()),
                pixelSize: image.pixelSize
            ),
            position: position,
            timing: DeviceState.timing(),
            posture: DeviceState.posture(appVersion: appVersion),
            claims: claims,
            previousDigest: previousDigest
        )
        return try await assemble(
            payload: payload,
            nonce: nonce,
            profile: CapturePayload.profile,
            mediaDigest: mediaDigest
        )
    }

    /// Ramène l'instant de l'obturateur sur l'horloge murale, seule échelle
    /// où l'horodatage d'un point CoreLocation est comparable.
    private func shutterDate(of image: CapturedImage) -> Date {
        Date(timeIntervalSinceNow: image.shutterUptime - ProcessInfo.processInfo.systemUptime)
    }
}

public enum CaptureError: Error, CustomStringConvertible {
    case noPosition

    public var description: String {
        switch self {
        case .noPosition: return "aucun point de position : le profil capture l'exige"
        }
    }
}

#endif
