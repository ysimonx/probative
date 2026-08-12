import Foundation

/// Construction de la charge utile du **noyau** (profil `core`, spec §2.5).
///
/// Aucune dépendance système ici : ce fichier est du calcul pur, ce qui le
/// rend vérifiable sur l'hôte contre les vecteurs d'or. La collecte, elle,
/// vit dans ``DeviceState`` et n'est exerçable que sur appareil.
///
/// L'implémentation de référence reste `verifier-python/tests/factory.py` :
/// si ce code produit une charge utile que la fabrique ne saurait pas
/// produire, c'est ce code qui s'écarte de la spécification. Le pendant
/// Kotlin est `core/payload/Payload.kt` — les deux doivent rester
/// interchangeables champ pour champ.
public enum CorePayload {

    /// Profil déclaré dans l'en-tête protégé (label 102).
    public static let profile = "core"

    /// Assemble la charge utile. Les labels et leur obligation viennent de
    /// `spec/envelope-v0.1.cddl` : 1, 2, 4 et 5 obligatoires, 7 optionnel.
    ///
    /// Ni `position` (3) ni corroboration (6) : le noyau n'affirme rien du
    /// monde physique, et les ajouter ferait juste porter à l'enveloppe des
    /// champs qu'aucune propriété ne note (drapeau `UNGRADED_FIELDS`).
    public static func build(
        nonce: Data,
        media: Media,
        timing: Timing,
        posture: Posture,
        previousDigest: Data? = nil
    ) -> CborValue {
        precondition(!nonce.isEmpty, "nonce vide")
        var payload: [Int64: CborValue] = [
            1: .bytes(nonce),
            2: media.cbor,
            4: timing.cbor,
            5: posture.cbor,
        ]
        if let previousDigest {
            precondition(previousDigest.count == 32, "chaînage : SHA-256 de 32 octets attendu")
            payload[7] = .bytes(previousDigest)
        }
        return .map(payload)
    }
}

/// Bloc `media` : ce que l'enveloppe dit des octets scellés.
///
/// `digest` porte sur **les octets qui partiront au serveur**, jamais sur une
/// représentation intermédiaire — décoder puis ré-encoder une image produirait
/// un `MEDIA_DIGEST_MISMATCH` dont la cause serait illisible.
///
/// `pixelSize` (label 5) et `durationMs` (label 7) décrivent le médium et
/// n'ont de sens qu'après une acquisition : le profil `capture` exige l'un
/// **ou** l'autre — une image a des dimensions, un son une durée — et le noyau
/// n'en porte aucun, puisqu'il ne décrit que des octets.
public struct Media {
    public let digest: Data
    public let mimeType: String
    public let sizeBytes: Int
    public let signLatencyMs: Int
    public let pixelSize: (width: Int, height: Int)?
    public let durationMs: Int?

    public init(
        digest: Data,
        mimeType: String,
        sizeBytes: Int,
        signLatencyMs: Int,
        pixelSize: (width: Int, height: Int)? = nil,
        durationMs: Int? = nil
    ) {
        self.digest = digest
        self.mimeType = mimeType
        self.sizeBytes = sizeBytes
        self.signLatencyMs = signLatencyMs
        self.pixelSize = pixelSize
        self.durationMs = durationMs
    }

    /// Ce que le profil `capture` exige : une description du médium.
    var describesMedium: Bool { pixelSize != nil || durationMs != nil }

    var cbor: CborValue {
        precondition(digest.count == 32, "empreinte SHA-256 de 32 octets attendue")
        precondition(!mimeType.isEmpty, "type MIME vide")
        precondition(sizeBytes >= 0, "taille négative")
        precondition(signLatencyMs >= 0, "latence négative")
        var media: [Int64: CborValue] = [
            1: .text("sha-256"),
            2: .bytes(digest),
            3: .text(mimeType),
            4: .int(Int64(sizeBytes)),
            6: .int(Int64(signLatencyMs)),
        ]
        if let pixelSize {
            precondition(pixelSize.width > 0 && pixelSize.height > 0, "dimensions nulles")
            media[5] = .array([.int(Int64(pixelSize.width)), .int(Int64(pixelSize.height))])
        }
        if let durationMs {
            precondition(durationMs >= 0, "durée négative")
            media[7] = .int(Int64(durationMs))
        }
        return .map(media)
    }
}

/// Bloc `timing` : les trois horloges, plus l'état de synchronisation.
///
/// `wallMs` est falsifiable — c'est tout l'objet de R3 côté serveur, qui la
/// confronte à l'émission du nonce. On la transmet quand même : le serveur ne
/// peut mesurer l'écart que s'il voit ce que l'appareil croyait être l'heure.
public struct Timing {
    public let wallMs: Int64
    public let uptimeMs: Int64
    public let utcOffsetMinutes: Int
    public let automaticTime: Bool?

    public init(wallMs: Int64, uptimeMs: Int64, utcOffsetMinutes: Int, automaticTime: Bool? = nil) {
        self.wallMs = wallMs
        self.uptimeMs = uptimeMs
        self.utcOffsetMinutes = utcOffsetMinutes
        self.automaticTime = automaticTime
    }

    var cbor: CborValue {
        var timing: [Int64: CborValue] = [
            1: .int(wallMs),
            2: .int(uptimeMs),
            3: .int(Int64(utcOffsetMinutes)),
        ]
        if let automaticTime { timing[4] = .bool(automaticTime) }
        return .map(timing)
    }
}

/// Bloc `posture` : l'état déclaré de l'appareil.
///
/// **Déclaratif, donc faible** — le client collecte, le serveur juge
/// (invariant 1). Aucune de ces valeurs ne conditionne quoi que ce soit ici.
///
/// Les champs optionnels valent `nil` quand la mesure n'a **pas été faite**,
/// et ils sont alors omis de l'encodage. Émettre `false` reviendrait à
/// affirmer « j'ai regardé, il n'y a rien » : c'est exactement la réclamation
/// simulée que la règle d'A6 interdit, et le serveur n'aurait aucun moyen de
/// distinguer les deux.
///
/// Le label 9 — heuristiques de jailbreak — est le pendant iOS des labels 7
/// et 8 d'Android, qui n'existent pas ici. C'est voulu : le format raisonne
/// en propriétés, pas en plateformes (invariant 4).
public struct Posture {
    public let platform: String
    public let osVersion: String
    public let appVersion: String
    public let debuggerAttached: Bool
    public let simulatorSuspected: Bool
    public let jailbreakSuspected: Bool?

    public init(
        platform: String,
        osVersion: String,
        appVersion: String,
        debuggerAttached: Bool,
        simulatorSuspected: Bool,
        jailbreakSuspected: Bool? = nil
    ) {
        self.platform = platform
        self.osVersion = osVersion
        self.appVersion = appVersion
        self.debuggerAttached = debuggerAttached
        self.simulatorSuspected = simulatorSuspected
        self.jailbreakSuspected = jailbreakSuspected
    }

    var cbor: CborValue {
        precondition(platform == "ios" || platform == "android", "plateforme inconnue : \(platform)")
        var posture: [Int64: CborValue] = [
            1: .text(platform),
            2: .text(osVersion),
            3: .text(appVersion),
            4: .bool(debuggerAttached),
            5: .bool(simulatorSuspected),
        ]
        if let jailbreakSuspected { posture[9] = .bool(jailbreakSuspected) }
        return .map(posture)
    }
}
