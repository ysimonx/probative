import SwiftUI

/// Écran unique : un préambule d'autorisations, puis la sonde.
///
/// **La sonde ne part plus au lancement inconditionnellement.** Elle attend
/// que les autorisations soient acquises, et c'est ce qui rend une campagne
/// reproductible : sans ce préambule, chaque première exécution consommait ses
/// délais à afficher des boîtes de dialogue, et rendait un verdict dégradé
/// pour des raisons qui n'avaient rien à voir avec le format.
///
/// Une fois tout accordé, l'enchaînement automatique reprend — c'est lui qui
/// permet de piloter la sonde sans toucher l'écran, via
/// `devicectl … launch --console`.
struct ProbeView: View {

    private enum Probe: String, CaseIterable, Identifiable {
        case capture = "C4.2 — acquisition photo"
        case seal = "C4.1 — enveloppe complète"
        case attest = "C3 — vecteur App Attest"
        var id: String { rawValue }

        /// Seule l'acquisition touche caméra et position ; les deux autres
        /// n'ont besoin que du réseau.
        var needsSensors: Bool { self == .capture }
    }

    @StateObject private var permissions = Permissions()
    @State private var lines: [SealProbe.Line] = []
    @State private var running = false
    @State private var fixturePath: String?
    // La sonde en cours est celle qui part automatiquement.
    @State private var probe: Probe = .capture

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
                    row("caméra", permissions.camera)
                    row("position", permissions.location)
                    row("mouvement", permissions.motion)
                    row("réseau local", permissions.localNetwork)
                    if permissions.requesting {
                        Text("demande en cours…").font(.footnote)
                    } else if needsRequest {
                        Button("Tout autoriser") {
                            Task {
                                await permissions.requestAll()
                                await permissions.probeLocalNetwork()
                                startIfReady()
                            }
                        }
                    }
                } header: {
                    Text("autorisations")
                } footer: {
                    if blocked {
                        // Refusée ne se rattrape pas depuis l'application :
                        // proposer un bouton qui ne peut rien serait pire que
                        // de dire où aller.
                        Text("Une autorisation refusée se rétablit dans "
                            + "Réglages › probative, pas ici.")
                            .font(.caption2)
                    }
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
                    .disabled(running || permissions.requesting)
            }
        }
        .task {
            permissions.refresh()
            // Le réseau local se sonde toujours en premier : c'est la seule
            // autorisation qu'aucune interface ne sait interroger, et sa
            // première tentative échoue par construction. Autant qu'elle
            // échoue ici plutôt qu'au milieu d'une campagne.
            await permissions.probeLocalNetwork()
            if needsRequest {
                await permissions.requestAll()
                await permissions.probeLocalNetwork()
            }
            startIfReady()
        }
    }

    private var needsRequest: Bool {
        [permissions.camera, permissions.location, permissions.motion]
            .contains { $0 == .undetermined || $0 == .unknown }
    }

    private var blocked: Bool {
        [permissions.camera, permissions.location, permissions.motion]
            .contains(where: \.blocking)
    }

    private func row(_ name: String, _ state: Permissions.State) -> some View {
        HStack {
            Text(state.symbol)
                .foregroundStyle(state == .granted ? .green : (state.blocking ? .red : .secondary))
            Text(name)
            Spacer()
            Text(state.rawValue).font(.caption).foregroundStyle(.secondary)
        }
    }

    /// Ne lance que si la sonde choisie peut réellement aboutir : partir sans
    /// caméra ni position produirait un échec qui n'apprend rien.
    private func startIfReady() {
        guard !probe.needsSensors || permissions.readyForCapture else { return }
        start()
    }

    private func start() {
        guard !running else { return }
        running = true
        lines = []
        fixturePath = nil
        Task {
            // L'état des autorisations ouvre le journal — et il est *imprimé*,
            // pas seulement affiché : un extrait rapatrié par `--console` doit
            // se lire sans l'écran, sinon on ne saura pas distinguer un capteur
            // muet d'une autorisation manquante.
            // Relu au moment du lancement, jamais hérité du préambule :
            // l'autorisation de mouvement se décide pendant que la demande
            // court, et l'état capturé plus tôt affichait « ? » alors que le
            // baromètre répondait. Un en-tête faux est pire qu'absent.
            permissions.refresh()
            let entete = "autorisations    \(permissions.summary)"
            print("[probe] \(entete)")
            var log = [SealProbe.Line(text: entete, failed: false)]
            switch probe {
            case .capture:
                log += await SealProbe.run(.capture)
            case .seal:
                log += await SealProbe.run(.core)
            case .attest:
                let result = await AttestProbe.run()
                log += result.lines.map { SealProbe.Line(text: $0.text, failed: $0.failed) }
                if let fixture = result.fixture {
                    fixturePath = AttestProbe.write(fixture)?.lastPathComponent
                }
            }
            lines = log
            running = false
        }
    }
}
