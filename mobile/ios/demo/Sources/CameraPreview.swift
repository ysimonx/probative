import AVFoundation
import ProbativeCore
import SwiftUI
import UIKit

/// L'aperçu — **écrit par l'application, alimenté par le cœur**.
///
/// C'est ADR-0008 rendu visible par un fichier : le cœur possède la caméra,
/// l'application possède l'écran. Il n'expose qu'une `AVCaptureSession` ; la
/// couche de prévisualisation, sa taille, sa place et son cadrage sont écrits
/// ici, dans la démonstration.
///
/// Ce que l'application ne fait **pas** : créer sa propre session. Deux
/// sessions concurrentes se disputent la caméra — mode de défaillance
/// prévisible de toute intégration naïve, et la raison pour laquelle un
/// intégrateur serait tenté d'utiliser une bibliothèque d'aperçu d'un côté et
/// le cœur de l'autre.
struct CameraPreview: UIViewRepresentable {

    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewUIView {
        let view = PreviewUIView()
        view.backgroundColor = .black
        view.layer.session = session
        return view
    }

    func updateUIView(_ view: PreviewUIView, context: Context) {
        view.layer.session = session
    }

    /// Une vue dont la couche **est** la couche de prévisualisation.
    ///
    /// Préférable à l'ajout d'une sous-couche : celle-ci suit alors le
    /// redimensionnement de la vue toute seule. Une sous-couche imposerait de
    /// recopier les dimensions à chaque passe de mise en page, et l'oublier
    /// produit un aperçu figé au premier cadre — décor trompeur, puisque la
    /// session tourne pourtant.
    final class PreviewUIView: UIView {
        override static var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }

        override var layer: AVCaptureVideoPreviewLayer {
            // swiftlint:disable:next force_cast
            super.layer as! AVCaptureVideoPreviewLayer
        }

        override func layoutSubviews() {
            super.layoutSubviews()
            layer.videoGravity = .resizeAspectFill
        }
    }
}

/// Détient la session de capture pour la durée de l'écran.
///
/// La session s'ouvre **à l'affichage**, pas au déclenchement : c'est tout
/// l'objet d'un aperçu. Le capteur est déjà sous tension et convergé quand on
/// appuie, ce que `CaptureTimings.idleMs` mesure — le temps de cadrage — et
/// `shutterLagMs` ce que la convergence coûte encore.
@MainActor
final class Viseur: ObservableObject {

    @Published private(set) var session: CaptureSession?
    @Published private(set) var echec: String?

    func ouvrir() async {
        guard session == nil else { return }
        do {
            session = try await CaptureSession.open()
        } catch let described as CustomStringConvertible {
            echec = described.description
        } catch {
            echec = error.localizedDescription
        }
    }

    /// Une session qui survit à l'écran garde le capteur sous tension et vide
    /// la batterie ; elle ne se referme pas toute seule.
    func fermer() {
        session?.close()
        session = nil
    }
}
