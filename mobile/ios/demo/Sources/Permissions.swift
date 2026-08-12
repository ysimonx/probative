import AVFoundation
import Foundation
import ProbativeCore
import SwiftUI

/// Préambule d'autorisations — **tout est demandé avant la première mesure**.
///
/// C'est la leçon de la campagne C4.2, et elle a coûté plusieurs essais. Une
/// autorisation sollicitée au moment où le capteur sert affiche sa boîte de
/// dialogue *pendant* que le délai d'attente court. Le relevé expire, et
/// chaque cas se présente sous un symptôme différent dont aucun ne nomme la
/// cause :
///
/// - **caméra** : la capture échoue sans image ;
/// - **position** : le délai expire, on croit à une panne de GPS ;
/// - **mouvement** : `baro-alt` et `baro` manquent, `position` perd sa
///   corroboration barométrique sans dire pourquoi ;
/// - **réseau local** : `-1009`, « The Internet connection appears to be
///   offline » — sur un appareil qui vient de joindre les serveurs d'Apple.
///
/// Aucune de ces quatre n'est vérifiable *a priori* de la même façon : trois
/// ont une interface d'état, la quatrième n'en a aucune et ne se constate
/// qu'en essayant. D'où cet écran, qui les rend toutes visibles avant de
/// lancer quoi que ce soit.
@MainActor
final class Permissions: ObservableObject {

    enum State: String {
        case granted = "accordée"
        case denied = "refusée"
        case undetermined = "à demander"
        case restricted = "restreinte"
        case unknown = "inconnue"

        var symbol: String {
            switch self {
            case .granted: return "✓"
            case .denied, .restricted: return "✗"
            case .undetermined, .unknown: return "?"
            }
        }

        var blocking: Bool { self == .denied || self == .restricted }

        init(_ authorization: Sensors.Authorization) {
            switch authorization {
            case .granted: self = .granted
            case .denied: self = .denied
            case .restricted: self = .restricted
            case .undetermined: self = .undetermined
            }
        }
    }

    @Published private(set) var camera: State = .unknown
    @Published private(set) var location: State = .unknown
    @Published private(set) var motion: State = .unknown
    /// Le réseau local n'a pas d'interface d'état : `unknown` tant qu'une
    /// requête n'a pas abouti, et c'est une limite du système, pas un oubli.
    @Published private(set) var localNetwork: State = .unknown
    @Published private(set) var requesting = false

    /// Toutes accordées, hors réseau local qui ne se sait qu'à l'usage.
    var readyForCapture: Bool {
        camera == .granted && location == .granted
    }

    /// Ce qui manque, en clair — pour un journal de campagne lisible sans
    /// l'écran sous les yeux.
    var summary: String {
        "camera \(camera.symbol) position \(location.symbol) "
            + "mouvement \(motion.symbol) reseau \(localNetwork.symbol)"
    }

    func refresh() {
        camera = cameraState()
        location = State(Sensors.locationAuthorization)
        motion = State(Sensors.motionAuthorization)
    }

    /// Demande les trois autorisations **en séquence**, jamais en parallèle :
    /// iOS n'affiche qu'une boîte de dialogue à la fois et jette
    /// silencieusement les demandes concurrentes.
    func requestAll() async {
        requesting = true
        defer { requesting = false }

        _ = await Camera.requestAccess()
        camera = cameraState()

        location = State(await Sensors.requestLocationAuthorization())

        // Le mouvement se demande en démarrant un relevé : c'est la seule
        // façon, et c'est pour cela qu'elle surprend en pleine capture.
        motion = State(await Sensors.requestMotionAuthorization())
    }

    /// Éprouve le réseau local en joignant réellement le serveur de dev.
    ///
    /// Il n'existe aucun moyen d'interroger cette autorisation ni de la
    /// demander à l'avance : la boîte de dialogue s'affiche à la première
    /// tentative, qui échoue. Cet appel est donc **fait pour échouer une
    /// fois**, hors du chemin de mesure — plutôt que de faire échouer la
    /// première campagne.
    func probeLocalNetwork() async {
        guard let server = DevServer.fromBundle() else {
            localNetwork = .unknown
            return
        }
        do {
            // Un `kid` inexistant : la route répond 400, ce qui suffit à
            // prouver que le réseau passe. On ne cherche pas un succès
            // fonctionnel, seulement l'accès.
            _ = try await server.nonce(kid: Data([0]), profile: "core")
            localNetwork = .granted
        } catch DevServer.Failure.refused {
            // Le serveur a répondu : le réseau est accessible.
            localNetwork = .granted
        } catch {
            localNetwork = .denied
        }
    }

    private func cameraState() -> State {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return .granted
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .undetermined
        @unknown default: return .unknown
        }
    }
}
