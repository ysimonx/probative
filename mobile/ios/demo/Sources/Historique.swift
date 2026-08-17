import Foundation

/// Une campagne et ce qu'elle a produit — conservée pour être relue.
///
/// L'historique existe parce qu'une campagne isolée ne dit rien de la
/// dispersion. Sur iPhone 16, deux acquisitions identiques ont rendu 1 904 ms
/// puis 2 494 ms de temps mural ; la calibration des seuils de `grading.py`
/// (étape C5) demandera *n* prises par appareil, et il faut pouvoir les
/// comparer sans recoller des extraits de console.
///
/// **Les octets sont conservés, pas seulement leurs empreintes.** L'enveloppe
/// ne porte qu'un condensat du média : sans les octets, le verdict sur le
/// contenu ne vaut plus rien, et aucune recompression ne les rattrape
/// (ADR-0007 point 5). On garde donc le tampon d'origine et on ne le décode
/// que pour l'affichage.
///
/// Mémoire seule : rien n'est persisté d'un lancement à l'autre. C'est un banc
/// de mesure, pas un stockage de preuves, et le laisser croire serait pire que
/// de ne rien garder.
struct Prise: Identifiable {
    let id = UUID()
    let index: Int
    /// Numéro de série. Une série close, la suivante repart d'une tête.
    let serie: Int
    let instant: Date
    let profil: String
    let niveau: String
    let motif: String
    /// Grade **et** evidence : le grade seul dirait « origin B » sans dire
    /// pourquoi, or c'est dans l'evidence que se lit ce qui a été établi.
    let proprietes: [String]
    let drapeaux: String
    /// `media[6]` tel que scellé — le seul chiffre confronté au seuil.
    let mediaSixMs: Int
    /// Octets du média, intacts. `nil` pour une enveloppe sans acquisition.
    let photo: Data?
    let largeur: Int
    let hauteur: Int
    let typeMime: String
    let enveloppe: Data
    let defiR1: String
    let kid: String
    /// Décomposition de l'acquisition, absente hors profil `capture`.
    let decomposition: String?

    var heure: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: instant)
    }

    /// Une ligne de tableau : ce qui distingue une prise d'une autre au premier
    /// coup d'œil.
    var ligne: String {
        var s = String(format: "%02d  s%d  %@  %@  %@", index, serie, heure,
                       profil.padding(toLength: 8, withPad: " ", startingAt: 0),
                       niveau.padding(toLength: 9, withPad: " ", startingAt: 0))
        s += String(format: "media[6] %4d ms", mediaSixMs)
        if let photo {
            s += String(format: "  %d×%d  %d ko", largeur, hauteur, photo.count / 1024)
        }
        return s
    }
}

/// Le tableau des prises, dans l'ordre où elles ont été faites.
@MainActor
final class Historique: ObservableObject {

    static let partage = Historique()

    @Published private(set) var prises: [Prise] = []

    func ajouter(_ prise: Prise) {
        prises.append(prise)
    }

    var compte: Int { prises.count }

    /// Dispersion de `media[6]` sur les prises d'un profil — la grandeur qui
    /// intéresse la calibration, et que trois relevés ne suffisent pas à fixer.
    func dispersion(profil: String) -> String {
        let valeurs = prises.filter { $0.profil == profil }.map(\.mediaSixMs).sorted()
        guard !valeurs.isEmpty else { return "aucune prise en \(profil)" }
        return String(
            format: "media[6] en %@ : %d prises, min %d, max %d, median %d ms",
            profil, valeurs.count, valeurs.first!, valeurs.last!, valeurs[valeurs.count / 2]
        )
    }
}
