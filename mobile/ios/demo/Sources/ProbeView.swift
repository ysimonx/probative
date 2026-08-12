import SwiftUI

/// Écran unique : la sonde C4.1 part au lancement, le journal s'affiche.
///
/// Le démarrage automatique n'est pas cosmétique — il permet de piloter la
/// sonde sans toucher l'écran, via `devicectl … launch --console`, et donc de
/// mener une campagne depuis un poste de développement.
///
/// **La sonde C3 reste accessible**, alors que C4.1 en est un sur-ensemble.
/// Elle seule produit le vecteur d'appareil (`c3-fixture.json`), socle des
/// tests de la phase D — et ce vecteur se périme : le certificat feuille de
/// l'attestation ne vaut que trois jours. Retirer le moyen de le régénérer
/// aurait transformé une campagne de dix minutes en fouille de l'historique.
struct ProbeView: View {

    private enum Probe: String, CaseIterable, Identifiable {
        case seal = "C4.1 — enveloppe complète"
        case attest = "C3 — vecteur App Attest"
        var id: String { rawValue }
    }

    @State private var lines: [SealProbe.Line] = []
    @State private var running = false
    @State private var fixturePath: String?
    @State private var probe: Probe = .seal

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("sonde", selection: $probe) {
                        ForEach(Probe.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .disabled(running)
                }
                Section {
                    ForEach(lines) { line in
                        Text(line.text)
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(line.failed ? .red : .primary)
                            .textSelection(.enabled)
                    }
                } footer: {
                    if let fixturePath {
                        Text("vecteur : \(fixturePath)")
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("probative")
            .toolbar {
                Button(running ? "en cours…" : "relancer", action: start)
                    .disabled(running)
            }
        }
        .task { start() }
    }

    private func start() {
        guard !running else { return }
        running = true
        lines = []
        fixturePath = nil
        Task {
            switch probe {
            case .seal:
                lines = await SealProbe.run()
            case .attest:
                let result = await AttestProbe.run()
                // Les deux sondes journalisent la même chose ; seul le type
                // diffère, et le convertir ici évite d'imposer un protocole
                // commun à deux sondes qui n'ont pas la même vie.
                lines = result.lines.map { SealProbe.Line(text: $0.text, failed: $0.failed) }
                if let fixture = result.fixture {
                    fixturePath = AttestProbe.write(fixture)?.lastPathComponent
                }
            }
            running = false
        }
    }
}
