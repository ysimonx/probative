import Foundation

/// Valeur CBOR du format `ac/0.1`.
///
/// Le format n'utilise que des maps à clés entières : le modèle le fige
/// dans le type plutôt que de le vérifier à l'exécution. Les conformités
/// aux littéraux rendent la construction des charges utiles lisible sans
/// rien céder sur le typage.
public indirect enum CborValue {
    case int(Int64)
    case bytes(Data)
    case text(String)
    case array([CborValue])
    case map([Int64: CborValue])
    case bool(Bool)
    case double(Double)
    case tag(UInt64, CborValue)
}

extension CborValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int64) { self = .int(value) }
}

extension CborValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .text(value) }
}

extension CborValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}

extension CborValue: ExpressibleByFloatLiteral {
    public init(floatLiteral value: Double) { self = .double(value) }
}

extension CborValue: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: CborValue...) { self = .array(elements) }
}

extension CborValue: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (Int64, CborValue)...) {
        self = .map(Dictionary(uniqueKeysWithValues: elements))
    }
}

/// Encodeur CBOR canonique, strict nécessaire du format `ac/0.1`.
///
/// Pas de bibliothèque généraliste, pour la même raison que côté serveur
/// (ADR-0001) : la surface doit rester minimale, et la canonicité est
/// validée octet à octet contre les vecteurs d'or du vérificateur, qui
/// font foi. Deux implémentations doivent produire des octets identiques
/// pour une même charge utile, sinon la signature ne se vérifie pas
/// (spec §7).
public enum Cbor {

    public static func encode(_ value: CborValue) -> Data {
        var out = Data()
        write(value, into: &out)
        return out
    }

    private static func write(_ value: CborValue, into out: inout Data) {
        switch value {
        case .int(let n):
            if n >= 0 {
                writeHead(major: 0, argument: UInt64(n), into: &out)
            } else {
                // ~n vaut -1 - n en complément à deux : pas de débordement,
                // même pour Int64.min.
                writeHead(major: 1, argument: UInt64(bitPattern: ~n), into: &out)
            }
        case .bytes(let data):
            writeHead(major: 2, argument: UInt64(data.count), into: &out)
            out.append(data)
        case .text(let string):
            let utf8 = Data(string.utf8)
            writeHead(major: 3, argument: UInt64(utf8.count), into: &out)
            out.append(utf8)
        case .array(let items):
            writeHead(major: 4, argument: UInt64(items.count), into: &out)
            for item in items { write(item, into: &out) }
        case .map(let entries):
            // Tri par octets d'encodage croissants (RFC 8949 §4.2.1). Le
            // format n'a que des clés entières positives : l'ordre coïncide
            // avec l'ordre numérique — et avec le tri de cbor2, la
            // référence. C'est l'encodage qui fait foi.
            writeHead(major: 5, argument: UInt64(entries.count), into: &out)
            let encoded = entries.map { key, value in
                (encode(.int(key)), encode(value))
            }
            for (key, value) in encoded.sorted(by: { $0.0.lexicographicallyPrecedes($1.0) }) {
                out.append(key)
                out.append(value)
            }
        case .bool(let flag):
            out.append(flag ? 0xF5 : 0xF4)
        case .double(let d):
            writeFloat(d, into: &out)
        case .tag(let tag, let inner):
            writeHead(major: 6, argument: tag, into: &out)
            write(inner, into: &out)
        }
    }

    /// Tête majeure + argument en forme la plus courte (RFC 8949 §4.2.1).
    private static func writeHead(major: UInt8, argument: UInt64, into out: inout Data) {
        let m = major << 5
        switch argument {
        case ..<24:
            out.append(m | UInt8(argument))
        case ...0xFF:
            out.append(m | 24)
            out.append(UInt8(argument))
        case ...0xFFFF:
            out.append(m | 25)
            appendBigEndian(argument, bytes: 2, into: &out)
        case ...0xFFFF_FFFF:
            out.append(m | 26)
            appendBigEndian(argument, bytes: 4, into: &out)
        default:
            out.append(m | 27)
            appendBigEndian(argument, bytes: 8, into: &out)
        }
    }

    private static func appendBigEndian(_ value: UInt64, bytes: Int, into out: inout Data) {
        for shift in stride(from: (bytes - 1) * 8, through: 0, by: -8) {
            out.append(UInt8((value >> shift) & 0xFF))
        }
    }

    // --- flottants : forme la plus courte qui préserve la valeur ---------
    //
    // Les trois largeurs coexistent dans une même charge utile (8.0 tient
    // en demi-précision, 48.2973 exige du float64). Émettre du float64
    // partout produirait des octets différents des vecteurs d'or — donc
    // une signature invalide côté serveur.

    private static func writeFloat(_ d: Double, into out: inout Data) {
        if d.isNaN {
            // NaN canonique unique : le format n'en transporte aucun, mais
            // l'encodeur ne doit pas pouvoir en produire deux formes.
            out.append(contentsOf: [0xF9, 0x7E, 0x00])
            return
        }
        if let half = halfBits(of: d) {
            out.append(0xF9)
            out.append(UInt8(half >> 8))
            out.append(UInt8(half & 0xFF))
            return
        }
        let f = Float(d)
        if Double(f) == d {
            out.append(0xFA)
            appendBigEndian(UInt64(f.bitPattern), bytes: 4, into: &out)
            return
        }
        out.append(0xFB)
        appendBigEndian(d.bitPattern, bytes: 8, into: &out)
    }

    /// Bits IEEE 754 demi-précision si la valeur y est exacte, sinon nil.
    /// Implémentation par bits, portable — `Float16` n'existe pas sur
    /// toutes les architectures d'hôte de test.
    private static func halfBits(of d: Double) -> UInt16? {
        let f = Float(d)
        guard Double(f) == d else { return nil }
        let bits = f.bitPattern
        let sign = UInt16((bits >> 16) & 0x8000)
        let exp32 = Int((bits >> 23) & 0xFF)
        let mant32 = bits & 0x7F_FFFF

        if exp32 == 0xFF {
            // ±Infini tient en demi-précision ; NaN est traité en amont.
            return sign | 0x7C00
        }
        if exp32 == 0 {
            // ±0.0 exact ; les sous-normaux float32 sont tous en dessous
            // du plus petit sous-normal half (2^-24).
            return mant32 == 0 ? sign : nil
        }

        let unbiased = exp32 - 127
        if (-14...15).contains(unbiased) {
            // Normal en half : 10 bits de mantisse, les 13 bas doivent être nuls.
            guard mant32 & 0x1FFF == 0 else { return nil }
            return sign | UInt16((unbiased + 15) << 10) | UInt16(mant32 >> 13)
        }
        if (-24 ... -15).contains(unbiased) {
            // Sous-normal en half : valeur = m × 2^-24, m sur 10 bits.
            let m = UInt32(0x80_0000) | mant32
            let shift = UInt32(-unbiased - 1)
            guard m & ((1 << shift) - 1) == 0 else { return nil }
            return sign | UInt16(m >> shift)
        }
        return nil
    }
}
