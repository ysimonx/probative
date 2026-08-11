import SwiftUI

/// Écran unique : la sonde part au lancement, le journal s'affiche.
///
/// Le démarrage automatique n'est pas cosmétique — il permet de piloter la
/// sonde sans toucher l'écran, via `devicectl ... launch --console`, et donc
/// de rapatrier le vecteur depuis un poste de développement.
struct ProbeView: View {
    @State private var lines: [AttestProbe.Line] = []
    @State private var running = false
    @State private var fixturePath: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(lines) { line in
                        Text(line.text)
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(line.failed ? .red : .primary)
                            .textSelection(.enabled)
                    }
                } header: {
                    Text("Sonde C3 — App Attest")
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
            let result = await AttestProbe.run()
            lines = result.lines
            if let fixture = result.fixture {
                fixturePath = AttestProbe.write(fixture)?.lastPathComponent
            }
            running = false
        }
    }
}
