#if os(iOS)

import AVFoundation
import Foundation

/// Ce que rend une acquisition photographique.
///
/// `jpeg` porte **les octets tels que le pipeline photo les a produits**.
/// C'est le piège le plus coûteux de cette étape : décoder en `UIImage` puis
/// ré-encoder change les octets, et le serveur rejetterait en
/// `MEDIA_DIGEST_MISMATCH` sans que la cause soit lisible. On hache ce tampon
/// tel quel, et on envoie ce même tampon.
public struct CapturedImage {
    public let jpeg: Data
    public let pixelSize: (width: Int, height: Int)
    /// Instant de l'obturateur sur l'horloge monotone — l'origine de
    /// `media[6]`, et la référence de l'âge du point de position.
    public let shutterUptime: TimeInterval
}

public enum CameraError: Error, CustomStringConvertible {
    case denied
    case unavailable
    case noData
    case timedOut
    case failed(String)

    public var description: String {
        switch self {
        case .denied: return "autorisation caméra refusée"
        case .unavailable: return "aucune caméra arrière disponible"
        case .noData: return "le pipeline photo n'a rendu aucun octet"
        case .timedOut: return "le pipeline photo n'a jamais rappelé"
        case .failed(let message): return "capture : \(message)"
        }
    }
}

/// Acquisition photographique par AVFoundation — **le cœur pilote la caméra**.
///
/// C'est le point d'entrée qui distingue le profil `capture` du noyau : le
/// cœur a observé l'acquisition, donc le chemin capteur→signature est court
/// et mesurable. Il ne prouve pas pour autant l'origine capteur — sur un
/// appareil compromis, une caméra virtuelle injecte des images dans le
/// pipeline. C'est une différence de degré, pas de nature, et c'est
/// exactement pourquoi le plafond de recapture existe (ADR-0005).
///
/// Aucune prévisualisation : la session vit le temps d'une photo. Un
/// intégrateur qui veut son propre écran passe par `seal(bytes)`, et obtient
/// alors le profil `core` — une preuve plus étroite, et honnête.
public enum Camera {

    /// Demande l'autorisation si elle n'a pas encore été accordée.
    public static func requestAccess() async -> Bool {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return true
        case .notDetermined: return await AVCaptureDevice.requestAccess(for: .video)
        default: return false
        }
    }

    /// Prend une photo et rend ses octets bruts. Bloquant côté matériel, donc
    /// `async` : la configuration de session ne doit pas tenir le fil
    /// principal, ce dont AVFoundation se plaint bruyamment.
    /// - Parameter timeout: délai de garde du pipeline photo. Il n'interrompt
    ///   jamais une capture lente — 2 s suffisent sur iPhone 16 — seulement une
    ///   capture morte.
    public static func capture(timeout: TimeInterval = 20) async throws -> CapturedImage {
        guard await requestAccess() else { throw CameraError.denied }

        let session = AVCaptureSession()
        session.sessionPreset = .photo

        guard
            let device = AVCaptureDevice.default(
                .builtInWideAngleCamera, for: .video, position: .back
            ),
            let input = try? AVCaptureDeviceInput(device: device)
        else { throw CameraError.unavailable }

        let output = AVCapturePhotoOutput()
        session.beginConfiguration()
        guard session.canAddInput(input), session.canAddOutput(output) else {
            session.commitConfiguration()
            throw CameraError.unavailable
        }
        session.addInput(input)
        session.addOutput(output)
        session.commitConfiguration()

        session.startRunning()
        defer { session.stopRunning() }

        // La session met un instant à converger (exposition, mise au point).
        // Déclencher immédiatement rend une image noire sur certains
        // appareils — ce n'est pas une erreur, juste une photo inutilisable.
        try? await Task.sleep(nanoseconds: 400_000_000)

        let settings = AVCapturePhotoSettings(
            format: [AVVideoCodecKey: AVVideoCodecType.jpeg]
        )
        let delegate = PhotoDelegate()
        return try await withCheckedThrowingContinuation { continuation in
            delegate.continuation = continuation
            // Le délégué n'est pas retenu par AVFoundation : sans cette
            // référence forte, il est libéré avant le rappel et la capture
            // ne rend jamais rien.
            delegate.retain = delegate
            delegate.armTimeout(timeout)
            output.capturePhoto(with: settings, delegate: delegate)
        }
    }

    private final class PhotoDelegate: NSObject, AVCapturePhotoCaptureDelegate {
        private let lock = NSLock()
        private var pending: CheckedContinuation<CapturedImage, Error>?
        var retain: PhotoDelegate?
        private var shutterUptime: TimeInterval = ProcessInfo.processInfo.systemUptime

        var continuation: CheckedContinuation<CapturedImage, Error>? {
            get { lock.withLock { pending } }
            set { lock.withLock { pending = newValue } }
        }

        /// Reprend la continuation **une seule fois**, quoi qu'il arrive.
        ///
        /// Sans ce garde-fou, `capture()` pouvait attendre indéfiniment : rien
        /// n'oblige AVFoundation à rappeler — une session interrompue par un
        /// appel entrant, par exemple, ne produit ni photo ni erreur. Un
        /// scellement suspendu sans message est le pire des échecs pour une
        /// campagne, puisqu'il ne laisse même pas de trace à lire.
        func finish(_ result: Result<CapturedImage, Error>) {
            lock.lock()
            let continuation = pending
            pending = nil
            lock.unlock()
            guard let continuation else { return }
            retain = nil
            continuation.resume(with: result)
        }

        /// Délai de garde. Généreux à dessein : il ne doit jamais interrompre
        /// une capture lente, seulement une capture morte.
        func armTimeout(_ seconds: TimeInterval) {
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
                self?.finish(.failure(CameraError.timedOut))
            }
        }

        /// L'instant de l'obturateur est celui-ci — pas celui du rappel de
        /// fin, qui inclut l'encodage JPEG. La différence est exactement ce
        /// que `media[6]` doit mesurer.
        func photoOutput(
            _ output: AVCapturePhotoOutput,
            willCapturePhotoFor resolvedSettings: AVCaptureResolvedPhotoSettings
        ) {
            shutterUptime = ProcessInfo.processInfo.systemUptime
        }

        func photoOutput(
            _ output: AVCapturePhotoOutput,
            didFinishProcessingPhoto photo: AVCapturePhoto,
            error: Error?
        ) {
            if let error {
                finish(.failure(CameraError.failed(error.localizedDescription)))
                return
            }
            // `fileDataRepresentation` rend le conteneur JPEG complet, EXIF
            // compris. C'est ce tampon qui part au serveur et c'est lui qu'on
            // hache — jamais une image reconstruite.
            guard let data = photo.fileDataRepresentation() else {
                finish(.failure(CameraError.noData))
                return
            }
            let dimensions = photo.resolvedSettings.photoDimensions
            finish(
                .success(
                    CapturedImage(
                        jpeg: data,
                        pixelSize: (width: Int(dimensions.width), height: Int(dimensions.height)),
                        shutterUptime: shutterUptime
                    )
                )
            )
        }
    }
}

#endif
