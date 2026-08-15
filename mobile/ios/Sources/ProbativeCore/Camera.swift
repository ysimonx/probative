#if os(iOS)

import AVFoundation
import Foundation

/// Format d'encodage du chemin d'acquisition.
///
/// **Une seule source de vérité**, et c'est sa raison d'être. Le codec demandé
/// à AVFoundation et le type MIME inscrit dans `media[3]` sortent tous deux
/// d'ici. Ils vivaient auparavant dans deux littéraux indépendants : changer
/// le codec laissait l'enveloppe annoncer l'ancien type, **signé**, sans que
/// rien ne le voie — aucun test ne les confrontait, et le vérificateur ne le
/// peut pas, l'invariant 6 lui interdisant de connaître le type de contenu.
/// C'est le mode de défaillance décrit en spec §2.4 à propos des unités : rien
/// ne casse, la donnée est simplement fausse, aucun verdict ne le signale.
/// Voir ADR-0007 point 3.
public enum CaptureFormat {

    /// JPEG — le défaut, et un choix motivé plutôt qu'hérité.
    ///
    /// Ce n'est pas ce que produit iOS si on ne dit rien : un appareil récent
    /// encode en HEIC. La déviation est délibérée, et elle repose sur
    /// l'**opposabilité** — une pièce destinée à être opposée dans dix ans se
    /// conserve dans le format qu'on saura ouvrir dans dix ans. Elle se paie
    /// en taille, et en finesse du résidu de bruit de capteur si l'empreinte
    /// PRNU devenait un jour exploitable. Voir ADR-0007 points 1 et 7.
    case jpeg

    /// Ce qui est inscrit dans `media[3]`.
    public var mimeType: String {
        switch self {
        case .jpeg: return "image/jpeg"
        }
    }

    /// Ce qui est demandé au pipeline photo.
    var codec: AVVideoCodecType {
        switch self {
        case .jpeg: return .jpeg
        }
    }
}

/// Ce que rend une acquisition photographique.
///
/// `bytes` porte **les octets tels que le pipeline photo les a produits**, et
/// `format` dit dans quel encodage. Les deux voyagent ensemble pour que le
/// type MIME de l'enveloppe ne puisse pas contredire ce qui a réellement été
/// encodé.
///
/// Le champ ne se nomme plus d'après son format. Le nommer `jpeg` gravait
/// l'encodage dans une API publique, et faisait d'un futur changement une
/// rupture d'interface au lieu d'un réglage — alors que `media[3]` est déclaré
/// par capture et qu'une version mineure peut ajouter un format sans casser
/// une enveloppe existante. Voir ADR-0007 point 2.
///
/// **Ne jamais ré-encoder.** C'est le piège le plus coûteux de cette étape :
/// décoder en `UIImage` puis ré-encoder change les octets, et le serveur
/// rejetterait en `MEDIA_DIGEST_MISMATCH` sans que la cause soit lisible. On
/// hache ce tampon tel quel, et on envoie ce même tampon.
///
/// La règle ne s'arrête pas à la sortie du cœur. L'enveloppe ne portant qu'une
/// **empreinte**, ces octets-là doivent être archivés intacts : recompression,
/// nettoyage d'EXIF, redimensionnement ou normalisation d'orientation rompent
/// la liaison sans rattrapage possible, et un verdict sur le contenu qu'on ne
/// peut plus produire ne vaut rien. Les dérivés se fabriquent à côté, jamais à
/// la place. Voir ADR-0007 points 4 et 5, et spec §2.3.
public struct CapturedImage {
    public let bytes: Data
    public let format: CaptureFormat
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
    /// - Parameter format: encodage demandé au pipeline photo. Le type MIME de
    ///   l'enveloppe en découle, il n'est jamais choisi séparément.
    /// - Parameter timeout: délai de garde du pipeline photo. Il n'interrompt
    ///   jamais une capture lente — 2 s suffisent sur iPhone 16 — seulement une
    ///   capture morte.
    public static func capture(
        format: CaptureFormat = .jpeg,
        timeout: TimeInterval = 20
    ) async throws -> CapturedImage {
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
            format: [AVVideoCodecKey: format.codec]
        )
        let delegate = PhotoDelegate(format: format)
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

        /// Le format demandé au pipeline, reporté tel quel dans le résultat :
        /// c'est ce qui interdit à `media[3]` de diverger du codec réellement
        /// utilisé.
        private let format: CaptureFormat

        init(format: CaptureFormat) {
            self.format = format
        }

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
        /// fin, qui inclut l'encodage. La différence est exactement ce que
        /// `media[6]` doit mesurer, et c'est aussi par elle qu'un format plus
        /// lourd se paierait : le coût d'encodage entre dans la latence, pas
        /// à côté.
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
            // `fileDataRepresentation` rend le conteneur complet, EXIF
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
                        bytes: data,
                        format: format,
                        pixelSize: (width: Int(dimensions.width), height: Int(dimensions.height)),
                        shutterUptime: shutterUptime
                    )
                )
            )
        }
    }
}

#endif
