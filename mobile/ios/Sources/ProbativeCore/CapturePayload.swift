import Foundation

/// Construction de la charge utile du profil **`capture`** (spec §2.5).
///
/// Le noyau plus trois exigences : une `position`, une description du médium
/// (`media[5]` **ou** `media[7]`), et la corroboration qui rend la position
/// défendable. En échange, une propriété de plus est notée — et un plafond
/// s'applique : `origin` ne dépasse pas B tant que la recapture analogique
/// n'est pas détectée (ADR-0005).
///
/// Comme ``CorePayload``, du calcul pur : aucune dépendance système, donc
/// vérifiable sur l'hôte contre le vecteur d'or `ios`.
public enum CapturePayload {

    /// Profil déclaré dans l'en-tête protégé (label 102).
    public static let profile = "capture"

    /// Assemble la charge utile d'une acquisition.
    ///
    /// Les `claims` ne sont pas décoratives. Sur iOS, l'absence d'indicateur
    /// de position simulée est **structurelle** — le système n'en expose
    /// aucun — et le vérificateur exige donc une corroboration inertielle en
    /// contrepoids : sans réclamation `motion` ou `steps`, `position` ne
    /// dépasse pas le grade C. La réclamation `baro-alt`, elle, est le signal
    /// le plus rentable des deux plateformes, parce qu'un simulateur de GNSS
    /// ne falsifie jamais la pression atmosphérique.
    public static func build(
        nonce: Data,
        media: Media,
        position: Position,
        timing: Timing,
        posture: Posture,
        claims: [Claim] = [],
        previousDigest: Data? = nil
    ) -> CborValue {
        precondition(!nonce.isEmpty, "nonce vide")
        // Le profil exige une description du médium — dimensions pour un
        // médium spatial, durée pour un médium temporel. La faute est
        // d'appelant : le serveur la rejetterait, mais bien plus tard.
        precondition(
            media.describesMedium,
            "profil capture : media[5] (dimensions) ou media[7] (durée) exigé"
        )
        var payload: [Int64: CborValue] = [
            1: .bytes(nonce),
            2: media.cbor,
            3: position.cbor,
            4: timing.cbor,
            5: posture.cbor,
        ]
        // Le CDDL veut `[+ claim]` : une liste présente est non vide. Aucune
        // mesure obtenue s'omet, plutôt que d'encoder un tableau vide qui
        // affirmerait avoir cherché.
        if !claims.isEmpty {
            payload[6] = .array(claims.map(\.cbor))
        }
        if let previousDigest {
            precondition(previousDigest.count == 32, "chaînage : SHA-256 de 32 octets attendu")
            payload[7] = .bytes(previousDigest)
        }
        return .map(payload)
    }
}

/// Bloc `position` : où le cœur croyait être au déclenchement.
///
/// `fixAgeMs` est un **âge**, pas un horodatage : l'écart entre l'instant du
/// point et celui de l'obturateur. Il faut donc conserver les deux instants
/// pour le calculer, ce qu'un champ d'horodatage seul n'aurait pas permis.
/// Au-delà du seuil de politique, le point ne prouve plus rien sur l'instant
/// de la capture.
public struct Position {

    /// Origine du point. Le format ferme la liste : un fournisseur inconnu
    /// se déclare `unknown` plutôt que de s'inventer un nom, sans quoi le
    /// serveur devrait tenir un registre de chaînes libres.
    public enum Provider: String {
        case gnss, fused, network, unknown
    }

    public let latitude: Double
    public let longitude: Double
    public let horizontalAccuracy: Double
    public let altitude: Double?
    public let verticalAccuracy: Double?
    public let provider: Provider
    public let fixAgeMs: Int

    public init(
        latitude: Double,
        longitude: Double,
        horizontalAccuracy: Double,
        altitude: Double? = nil,
        verticalAccuracy: Double? = nil,
        provider: Provider,
        fixAgeMs: Int
    ) {
        self.latitude = latitude
        self.longitude = longitude
        self.horizontalAccuracy = horizontalAccuracy
        self.altitude = altitude
        self.verticalAccuracy = verticalAccuracy
        self.provider = provider
        self.fixAgeMs = fixAgeMs
    }

    var cbor: CborValue {
        precondition(fixAgeMs >= 0, "âge de point négatif")
        var position: [Int64: CborValue] = [
            1: .double(latitude),
            2: .double(longitude),
            3: .double(horizontalAccuracy),
            6: .text(provider.rawValue),
            7: .int(Int64(fixAgeMs)),
        ]
        if let altitude { position[4] = .double(altitude) }
        if let verticalAccuracy { position[5] = .double(verticalAccuracy) }
        // Le nombre de satellites (label 8) n'est pas ici : iOS ne l'expose
        // pas, et l'inventer serait une réclamation simulée. Le label reste
        // optionnel au CDDL, ce qui absorbe l'écart (invariant 4).
        return .map(position)
    }
}

/// Une mesure de corroboration (spec §2.4) — extensible par construction :
/// le noyau ne connaît aucun type de réclamation en particulier.
///
/// `value` est libre par le format (`any` au CDDL). Deux conventions valent
/// pourtant d'être tenues, parce que le serveur les compare :
///
/// - **`baro-alt` est en mètres**, pour être confrontable à `position[4]` ;
/// - **`baro` est en hectopascals**, l'unité que rend nativement Android
///   (`Sensor.TYPE_PRESSURE`). iOS donne des kilopascals et doit convertir —
///   sans quoi deux plateformes rapporteraient la même mesure d'un facteur
///   dix, et rien dans le format ne le dirait.
public struct Claim {
    public let type: String
    public let source: String
    public let uptimeMs: Int
    public let value: CborValue

    public init(type: String, source: String, uptimeMs: Int, value: CborValue) {
        self.type = type
        self.source = source
        self.uptimeMs = uptimeMs
        self.value = value
    }

    var cbor: CborValue {
        precondition(!type.isEmpty, "type de réclamation vide")
        precondition(uptimeMs >= 0, "horodatage monotone négatif")
        return .map([
            1: .text(type),
            2: .text(source),
            3: .int(Int64(uptimeMs)),
            4: value,
        ])
    }
}
