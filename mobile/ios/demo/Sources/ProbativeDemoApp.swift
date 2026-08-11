import SwiftUI

/// Application de démonstration du cœur iOS — support d'exécution de la sonde
/// C3 sur appareil réel. Elle n'a pas d'autre raison d'être : App Attest exige
/// un App ID provisionné, qu'un simple bundle de test XCTest n'a pas.
@main
struct ProbativeDemoApp: App {
    var body: some Scene {
        WindowGroup {
            ProbeView()
        }
    }
}
