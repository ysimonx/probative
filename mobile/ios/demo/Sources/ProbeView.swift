import ImageIO
import SwiftUI
import UIKit

/// Écran unique : l'aperçu, le tableau des prises, et la fiche de chacune.
///
/// Le parcours est celui de la démonstration Android, et il vient d'un constat
/// d'usage : basculer sur un écran de résultat après le déclenchement retirait
/// la vue d'aperçu de la fenêtre, donc **détruisait la surface pendant la
/// capture**. Outre l'aperçu qui s'éteignait, cela faussait la mesure — la
/// convergence 3A y paraissait quatre fois plus longue qu'elle n'est.
///
/// Rien ne bouge donc tant que la caméra travaille : le résultat s'annonce sur
/// une ligne d'état, la ligne s'ajoute au tableau, et le détail se consulte
/// quand on le veut.
struct ProbeView: View {

    @StateObject private var permissions = Permissions()
    @StateObject private var viseur = Viseur()
    @StateObject private var historique = Historique.partage

    @State private var lines: [SealProbe.Line] = []
    @State private var running = false
    @State private var statut = "pret"
    @State private var fiche: Prise?
    @State private var journalVisible = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                autorisations

                if let session = viseur.session {
                    CameraPreview(session: session.avSession)
                        .frame(maxWidth: .infinity)
                        .frame(height: 260)
                } else if let echec = viseur.echec {
                    Text("viseur indisponible : \(echec)")
                        .font(.footnote).foregroundStyle(.red).padding()
                } else {
                    ProgressView().frame(height: 260)
                }

                Button {
                    lancer(.capture)
                } label: {
                    Text("＋  prendre une photo")
                        .font(.title3).frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .disabled(running || !permissions.readyForCapture)
                .padding(.horizontal)

                Text(statut)
                    .font(.footnote).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal).padding(.top, 4)

                tableau
            }
            .navigationTitle("probative")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("journal") { journalVisible = true }
                }
                ToolbarItem(placement: .topBarLeading) {
                    // La sonde sans caméra reste accessible : elle isole ce qui
                    // ne dépend pas de l'acquisition.
                    Button("core") { lancer(.core) }.disabled(running)
                }
            }
        }
        .sheet(item: $fiche) { FicheView(prise: $0) }
        .sheet(isPresented: $journalVisible) { JournalView(lines: lines) }
        .task {
            permissions.refresh()
            // Le réseau local se sonde en premier : c'est la seule autorisation
            // qu'aucune interface ne sait interroger, et sa première tentative
            // échoue par construction. Autant qu'elle échoue ici.
            await permissions.probeLocalNetwork()
            if needsRequest {
                await permissions.requestAll()
                await permissions.probeLocalNetwork()
            }
            await viseur.ouvrir()
        }
        .onDisappear { viseur.fermer() }
    }

    // -- Blocs ------------------------------------------------------------

    private var autorisations: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(permissions.summary)
                .font(.system(.caption, design: .monospaced))
            if blocked {
                // Refusée ne se rattrape pas depuis l'application : proposer un
                // bouton qui ne peut rien serait pire que de dire où aller.
                Text("Une autorisation refusée se rétablit dans Réglages › probative.")
                    .font(.caption2).foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal).padding(.bottom, 4)
    }

    private var tableau: some View {
        List {
            Section {
                if historique.prises.isEmpty {
                    Text("aucune prise").foregroundStyle(.secondary)
                }
                ForEach(historique.prises.reversed()) { prise in
                    Button { fiche = prise } label: {
                        Text(prise.ligne)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.primary)
                    }
                }
            } header: {
                Text(historique.prises.isEmpty
                     ? "tableau"
                     : "\(historique.compte) prise(s) — toucher une ligne")
            }
        }
        .listStyle(.plain)
    }

    private var needsRequest: Bool {
        [permissions.camera, permissions.location, permissions.motion]
            .contains { $0 == .undetermined || $0 == .unknown }
    }

    private var blocked: Bool {
        [permissions.camera, permissions.location, permissions.motion]
            .contains(where: \.blocking)
    }

    /// Lance une campagne **sans quitter l'écran** — voir la note de type.
    private func lancer(_ mode: SealProbe.Mode) {
        guard !running else { return }
        running = true
        statut = "campagne en cours…"
        Task {
            // L'état des autorisations est relu au lancement, jamais hérité du
            // préambule : il a pu changer entre-temps, et un en-tête faux est
            // pire qu'absent.
            permissions.refresh()
            let entete = "autorisations    \(permissions.summary)"
            print("[probe] \(entete)")

            let resultat = await SealProbe.run(mode, session: viseur.session)
            lines = [SealProbe.Line(text: entete, failed: false)] + resultat.lines
            if let prise = resultat.prise {
                historique.ajouter(prise)
                statut = "prise n°\(prise.index) : \(prise.profil) — \(prise.niveau), "
                    + "media[6] \(prise.mediaSixMs) ms"
            } else {
                statut = "campagne en échec — voir le journal"
            }
            running = false
        }
    }
}

/// La fiche d'une prise : la photo, le verdict, et les octets.
private struct FicheView: View {
    let prise: Prise
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let vignette = Self.vignette(prise.photo) {
                        Image(uiImage: vignette)
                            .resizable().scaledToFit()
                            .frame(maxWidth: .infinity)
                    }
                    Text(texte)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                .padding()
            }
            .navigationTitle("prise n°\(prise.index)")
            .toolbar { Button("fermer") { dismiss() } }
        }
    }

    private var texte: String {
        var s = ""
        s += "niveau         \(prise.niveau)\n"
        s += "motif          \(prise.motif)\n"
        s += "profil         \(prise.profil)\n"
        for p in prise.proprietes { s += "  \(p)\n" }
        s += "drapeaux       \(prise.drapeaux)\n\n"
        s += "media[6]       \(prise.mediaSixMs) ms — seul chiffre confronte au seuil\n"
        if let d = prise.decomposition { s += "acquisition    \(d)\n" }
        s += "\n"
        if let photo = prise.photo {
            s += "media          \(prise.largeur)×\(prise.hauteur), \(prise.typeMime)\n"
            s += "               \(photo.count) octets, tels que scelles\n"
        } else {
            s += "media          octets remis, \(prise.typeMime)\n"
        }
        s += "enveloppe      \(prise.enveloppe.count) octets\n"
        s += "kid            \(prise.kid)\n"
        s += "defi R1        \(prise.defiR1)\n\n"
        s += "enveloppe (base64, selectionnable) :\n"
        s += prise.enveloppe.base64EncodedString()
        return s
    }

    /// Vignette **sous-échantillonnée**. Décoder une image 4032×3024 en pleine
    /// résolution coûterait une cinquantaine de mégaoctets ; les octets
    /// conservés, eux, restent intacts — on ne montre jamais autre chose que ce
    /// qui a été scellé, mais on ne le montre pas en pleine taille.
    private static func vignette(_ data: Data?) -> UIImage? {
        guard let data, let source = CGImageSourceCreateWithData(data as CFData, nil) else {
            return nil
        }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: 900,
            // **Sans cette ligne la vignette sort tournée de 90°.** Le pipeline
            // photo n'oriente pas les pixels : il pose une balise EXIF, et
            // ImageIO ne l'applique que si on le demande.
            //
            // Le correctif appartient à l'afficheur, et à lui seul. Réécrire le
            // fichier pour « redresser » l'image romprait la liaison au
            // contenu — la spec §2.3 nomme la normalisation d'orientation parmi
            // ce qui détruit sans rattrapage. Les octets sont justes ; c'est la
            // vue qui les lisait mal.
            kCGImageSourceCreateThumbnailWithTransform: true,
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}

/// Le journal complet de la dernière campagne.
private struct JournalView: View {
    let lines: [SealProbe.Line]
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(lines) { line in
                        Text(line.text)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(line.failed ? .red : .primary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding()
            }
            .navigationTitle("journal")
            .toolbar { Button("fermer") { dismiss() } }
        }
    }
}
