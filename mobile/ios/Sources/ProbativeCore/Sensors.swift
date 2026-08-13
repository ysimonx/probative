#if os(iOS)

import CoreLocation
import CoreMotion
import Foundation

/// Collecte de la position et des mesures de corroboration.
///
/// Rien n'est jugé ici (invariant 1). Une mesure qu'on n'obtient pas est
/// **omise**, jamais remplacée par une valeur par défaut : le serveur doit
/// pouvoir distinguer « rien détecté » de « rien cherché », et une
/// réclamation simulée est la façon la plus simple de mentir sans en avoir
/// l'air.
public enum Sensors {

    // MARK: - Autorisations

    /// État d'une autorisation, sans le vocabulaire propre à chaque cadre.
    ///
    /// La distinction qui compte est `undetermined` contre `denied` : la
    /// première se règle en demandant, la seconde exige un détour par les
    /// réglages du système. Les confondre fait proposer un bouton qui ne peut
    /// rien.
    public enum Authorization: String {
        case granted, denied, undetermined, restricted
    }

    /// **À demander avant l'acquisition, jamais pendant.**
    ///
    /// Une autorisation sollicitée au moment où le capteur sert affiche sa
    /// boîte de dialogue *pendant* que le délai d'attente court : le relevé
    /// expire, et l'échec ressemble à une panne de capteur. Constaté sur les
    /// trois autorisations en C4.2 — position, caméra et mouvement — chacune
    /// avec un symptôme différent et aucun qui nomme la cause.
    ///
    /// L'appel est idempotent : accordée, il rend immédiatement.
    public static func requestLocationAuthorization() async -> Authorization {
        if locationAuthorization != .undetermined { return locationAuthorization }
        let delegate = AuthorizationDelegate()
        return await delegate.request()
    }

    public static var locationAuthorization: Authorization {
        switch CLLocationManager().authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse: return .granted
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .undetermined
        @unknown default: return .undetermined
        }
    }

    /// Autorisation « mouvement et forme » — celle du baromètre et du
    /// podomètre.
    ///
    /// Aucune interface ne la demande explicitement : elle se sollicite en
    /// démarrant un relevé, et c'est pour cela qu'elle surprend. On la
    /// provoque donc ici, une fois, hors du chemin de capture.
    public static var motionAuthorization: Authorization {
        switch CMAltimeter.authorizationStatus() {
        case .authorized: return .granted
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .undetermined
        @unknown default: return .undetermined
        }
    }

    public static func requestMotionAuthorization() async -> Authorization {
        if motionAuthorization != .undetermined { return motionAuthorization }
        // Un relevé suffit à déclencher la demande ; sa valeur ne nous
        // intéresse pas, seul l'état qui en résulte compte.
        _ = await firstPressure()
        return motionAuthorization
    }

    // MARK: - Position

    /// Attend un point de localisation, ou rend `nil` au bout du délai.
    ///
    /// L'autorisation « pendant l'utilisation » suffit : le cœur ne relève
    /// une position qu'au déclenchement, jamais en arrière-plan.
    /// - Parameter maxAge: âge au-delà duquel un point ne suffit pas et
    ///   l'attente continue. Le premier point que rend CoreLocation est
    ///   presque toujours **celui du cache** : mesuré à 43 s sur iPhone 16, il
    ///   faisait tomber `position` à C pour « point vieux au déclenchement »
    ///   alors qu'un point frais arrivait une seconde plus tard.
    ///
    ///   Attendre n'est pas filtrer : si le délai expire, le point le plus
    ///   frais obtenu est rendu **avec son âge réel**, et c'est le serveur qui
    ///   en juge (invariant 1). On ne cache jamais l'ancienneté d'un point, on
    ///   se donne seulement la chance d'en avoir un meilleur.
    public static func location(
        timeout: TimeInterval = 15,
        maxAge: TimeInterval = 5
    ) async -> CLLocation? {
        let delegate = LocationDelegate()
        return await delegate.waitForFix(timeout: timeout, maxAge: maxAge)
    }

    /// Convertit un point CoreLocation en bloc `position` du format.
    ///
    /// `fixAge` se mesure **par rapport à l'obturateur**, pas à l'instant de
    /// l'appel : c'est ce que `position[7]` décrit, et l'écart se voit dès
    /// qu'une capture prend une seconde.
    ///
    /// Le fournisseur est déclaré `gnss` quand la précision est de qualité
    /// satellitaire, `fused` sinon. iOS ne dit pas lequel de ses capteurs a
    /// produit le point — c'est une lecture, pas une mesure, et la nommer
    /// autrement serait se donner une certitude qu'on n'a pas.
    public static func position(from location: CLLocation, shutterDate: Date) -> Position {
        let ageMs = max(0, Int(shutterDate.timeIntervalSince(location.timestamp) * 1000))
        let horizontal = location.horizontalAccuracy
        return Position(
            latitude: location.coordinate.latitude,
            longitude: location.coordinate.longitude,
            horizontalAccuracy: horizontal,
            // Une précision verticale négative signale une altitude
            // indisponible : on omet les deux plutôt que d'encoder un
            // nombre qui ne veut rien dire.
            altitude: location.verticalAccuracy > 0 ? location.altitude : nil,
            verticalAccuracy: location.verticalAccuracy > 0 ? location.verticalAccuracy : nil,
            provider: horizontal > 0 && horizontal <= 20 ? .gnss : .fused,
            fixAgeMs: ageMs
        )
    }

    // MARK: - Corroboration

    /// Réclamations de corroboration, collectées en parallèle et bornées.
    ///
    /// Sur iOS, ce n'est pas optionnel : l'absence d'indicateur de position
    /// simulée est structurelle, et le vérificateur exige une corroboration
    /// inertielle en contrepoids — sans `motion` ni `steps`, `position` ne
    /// dépasse pas le grade C.
    ///
    /// **À lancer en même temps que l'acquisition, jamais après.** Mesuré sur
    /// iPhone 16 : collectée en aval de l'obturateur, la corroboration
    /// ajoutait 4,2 s à `media[6]` et faisait tomber `origin` à C pour
    /// « latence anormale » — le champ censé discriminer une injection
    /// n'accusait que l'ordonnancement du client. Les mesures encadrent la
    /// capture, elles ne la suivent pas.
    ///
    /// Chaque réclamation porte **son propre** horodatage de mesure (label 3),
    /// et non celui de l'obturateur : c'est ce que le CDDL décrit, et c'est la
    /// seule lecture qui garde un sens quand les mesures sont concurrentes.
    public static func claims() async -> [Claim] {
        async let altitude = barometricClaims()
        async let motion = motionClaim()
        async let steps = stepsClaim()
        return await altitude + [motion, steps].compactMap { $0 }
    }

    /// Horodatage monotone d'une mesure, en millisecondes — l'échelle du
    /// label 3, commune à `timing[2]`.
    private static var nowMs: Int {
        Int((ProcessInfo.processInfo.systemUptime * 1000).rounded())
    }

    /// `baro-alt` en **mètres** et `baro` en **hectopascals**.
    ///
    /// L'altitude absolue vient de `startAbsoluteAltitudeUpdates`, et pas de
    /// l'altitude *relative* : cette dernière ne mesure qu'un écart depuis le
    /// début des relevés, et la comparer à l'altitude GNSS n'aurait aucun
    /// sens. C'est pourtant l'API qu'on rencontre en premier.
    ///
    /// L'unité de `baro` est convertie depuis les kilopascals de CoreMotion :
    /// Android rend des hectopascals nativement, et deux plateformes qui
    /// rapporteraient la même mesure à un facteur dix près sans que rien
    /// dans le format ne le dise seraient un piège durable.
    private static func barometricClaims() async -> [Claim] {
        guard CMAltimeter.isRelativeAltitudeAvailable() else { return [] }

        // Les deux relevés sont **concurrents**. Enchaînés, leurs délais
        // d'expiration s'additionnaient : quatre secondes au lieu de deux
        // quand le baromètre ne répond pas — le cas ordinaire tant que
        // l'autorisation de mouvement n'a pas été accordée.
        async let absolute = absoluteAltitude()
        async let pressure = firstPressure()

        var claims: [Claim] = []
        if let absolute = await absolute {
            claims.append(
                Claim(
                    type: "baro-alt", source: "barometer",
                    uptimeMs: nowMs, value: .double(absolute)
                )
            )
        }
        if let kPa = await pressure {
            claims.append(
                Claim(
                    type: "baro", source: "barometer",
                    uptimeMs: nowMs, value: .double(kPa * 10)
                )
            )
        }
        return claims
    }

    private static func absoluteAltitude() async -> Double? {
        guard #available(iOS 15.0, *), CMAltimeter.isAbsoluteAltitudeAvailable() else {
            return nil
        }
        return await firstAbsoluteAltitude()
    }

    @available(iOS 15.0, *)
    private static func firstAbsoluteAltitude() async -> Double? {
        await withCheckedContinuation { continuation in
            let altimeter = CMAltimeter()
            let box = OnceBox<Double?>(continuation: continuation) { altimeter.stopAbsoluteAltitudeUpdates() }
            altimeter.startAbsoluteAltitudeUpdates(to: .main) { data, _ in
                box.finish(data.map { $0.altitude })
            }
            box.expire(after: 2, with: nil)
        }
    }

    private static func firstPressure() async -> Double? {
        await withCheckedContinuation { continuation in
            let altimeter = CMAltimeter()
            let box = OnceBox<Double?>(continuation: continuation) { altimeter.stopRelativeAltitudeUpdates() }
            altimeter.startRelativeAltitudeUpdates(to: .main) { data, _ in
                box.finish(data.map { $0.pressure.doubleValue })
            }
            box.expire(after: 2, with: nil)
        }
    }

    /// Quelques échantillons d'accéléromètre, horodatés en millisecondes
    /// depuis le premier — la forme qu'attend le vecteur d'or : une liste de
    /// `[dt, x, y, z]`.
    private static func motionClaim() async -> Claim? {
        let manager = CMMotionManager()
        guard manager.isAccelerometerAvailable else { return nil }
        manager.accelerometerUpdateInterval = 0.1
        manager.startAccelerometerUpdates()
        defer { manager.stopAccelerometerUpdates() }

        var samples: [CborValue] = []
        var origin: TimeInterval?
        for _ in 0 ..< 5 {
            try? await Task.sleep(nanoseconds: 100_000_000)
            guard let data = manager.accelerometerData else { continue }
            let start = origin ?? data.timestamp
            origin = start
            samples.append(
                .array([
                    .int(Int64(((data.timestamp - start) * 1000).rounded())),
                    .double(data.acceleration.x),
                    .double(data.acceleration.y),
                    .double(data.acceleration.z),
                ])
            )
        }
        guard !samples.isEmpty else { return nil }
        return Claim(
            type: "motion", source: "accelerometer",
            uptimeMs: nowMs, value: .array(samples)
        )
    }

    /// Pas comptés sur la dernière minute. Zéro est une mesure — un appareil
    /// posé sur une table en est une aussi — et se distingue de l'absence de
    /// podomètre, qui fait omettre la réclamation.
    private static func stepsClaim() async -> Claim? {
        guard CMPedometer.isStepCountingAvailable() else { return nil }
        let pedometer = CMPedometer()
        let steps: Int? = await withCheckedContinuation { continuation in
            let box = OnceBox<Int?>(continuation: continuation) {}
            pedometer.queryPedometerData(from: Date().addingTimeInterval(-60), to: Date()) {
                data, _ in
                box.finish(data.map { $0.numberOfSteps.intValue })
            }
            box.expire(after: 2, with: nil)
        }
        guard let steps else { return nil }
        return Claim(
            type: "steps", source: "pedometer",
            uptimeMs: nowMs, value: .int(Int64(steps))
        )
    }
}

/// Reprend une continuation **une seule fois**, quel que soit le nombre de
/// rappels et malgré l'expiration du délai.
///
/// CoreMotion appelle son bloc à répétition ; reprendre deux fois une
/// continuation est un plantage immédiat, pas une erreur silencieuse. Le
/// verrou est nécessaire : les rappels et le délai arrivent sur des files
/// différentes.
private final class OnceBox<T> {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Never>?
    private let cleanup: () -> Void

    init(continuation: CheckedContinuation<T, Never>, cleanup: @escaping () -> Void) {
        self.continuation = continuation
        self.cleanup = cleanup
    }

    func finish(_ value: T) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        guard let pending else { return }
        cleanup()
        pending.resume(returning: value)
    }

    func expire(after seconds: TimeInterval, with value: T) {
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
            self?.finish(value)
        }
    }
}

/// Demande d'autorisation de position, isolée de l'attente d'un point.
///
/// Séparée parce que les deux se confondent en pratique : `waitForFix`
/// sollicitait l'autorisation *et* attendait un relevé, si bien qu'un premier
/// lancement consommait tout son délai à afficher une boîte de dialogue.
/// Demande d'autorisation de position, isolée de l'attente d'un point.
///
/// Séparée parce que les deux se confondent en pratique : `waitForFix`
/// sollicitait l'autorisation *et* attendait un relevé, si bien qu'un premier
/// lancement consommait tout son délai à afficher une boîte de dialogue.
///
/// **`@unchecked Sendable` sous discipline explicite** : tout l'état mutable
/// n'est touché que sur la file principale. Ce n'est pas un contournement du
/// vérificateur de concurrence mais la seule forme possible ici —
/// `CLLocationManagerDelegate` n'est pas isolé, si bien qu'annoter la classe
/// `@MainActor` rend sa conformité illégale. La garantie est donc tenue par
/// construction, et énoncée ici pour qu'on ne la casse pas par mégarde.
private final class AuthorizationDelegate: NSObject, CLLocationManagerDelegate,
    @unchecked Sendable
{
    private var manager: CLLocationManager?
    private var box: OnceBox<Sensors.Authorization>?

    func request() async -> Sensors.Authorization {
        await withCheckedContinuation { continuation in
            // Créé sur la file principale : `CLLocationManager` exige un fil
            // doté d'une boucle d'exécution, faute de quoi ses rappels
            // n'arrivent jamais.
            DispatchQueue.main.async { [self] in
                box = OnceBox<Sensors.Authorization>(continuation: continuation) {}
                let manager = CLLocationManager()
                self.manager = manager
                manager.delegate = self
                manager.requestWhenInUseAuthorization()

                // L'utilisateur peut ne jamais répondre : on ne bloque pas la
                // sonde pour autant, et l'état rendu dit ce qu'il en est.
                DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
                    self?.box?.finish(.undetermined)
                }
            }
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = Sensors.locationAuthorization
        guard status != .undetermined else { return }
        box?.finish(status)
    }
}

/// Attente d'un point de localisation, avec autorisation à la demande.
///
/// **Même discipline que ci-dessus, et une raison de plus** : `freshest` est
/// écrit par les rappels de CoreLocation et lu à l'expiration du délai. Le
/// lire depuis une file de fond était une course de données, dont le pire cas
/// n'est pas une valeur périmée mais un sur-relâchement ARC. Tout est donc
/// touché sur la file principale, sans exception.
private final class LocationDelegate: NSObject, CLLocationManagerDelegate,
    @unchecked Sendable
{
    private var manager: CLLocationManager?
    private var box: OnceBox<CLLocation?>?
    private var freshest: CLLocation?
    private var maxAge: TimeInterval = 5

    func waitForFix(timeout: TimeInterval, maxAge: TimeInterval) async -> CLLocation? {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { [self] in
                self.maxAge = maxAge
                box = OnceBox<CLLocation?>(continuation: continuation) { [weak self] in
                    DispatchQueue.main.async { self?.manager?.stopUpdatingLocation() }
                }

                // Créé sur la file principale — sans quoi CoreLocation ne
                // délivre **jamais** ses rappels : aucune erreur, aucun
                // avertissement, juste un délai qui expire. Constaté sur
                // iPhone 16 en C4.2, et c'est le genre de panne qu'on impute
                // d'abord au GPS.
                let manager = CLLocationManager()
                self.manager = manager
                manager.delegate = self
                manager.desiredAccuracy = kCLLocationAccuracyBest
                manager.requestWhenInUseAuthorization()
                manager.startUpdatingLocation()

                // À l'expiration, on rend le meilleur point vu — pas `nil`.
                // Un point ancien reste une mesure, et son âge voyage avec
                // lui. La file principale garantit l'ordre : ce bloc est
                // enfilé après celui-ci, jamais avant.
                DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                    self?.box?.finish(self?.freshest)
                }
            }
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last else { return }
        // On garde le plus frais, et on ne s'arrête que sur un point
        // suffisamment récent : le premier rendu est presque toujours celui
        // du cache, vieux de plusieurs dizaines de secondes.
        if let known = freshest, known.timestamp > location.timestamp {
            return
        }
        freshest = location
        if -location.timestamp.timeIntervalSinceNow <= maxAge {
            box?.finish(location)
        }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        // Un échec ne doit pas jeter ce qu'on avait déjà obtenu.
        box?.finish(freshest)
    }
}

#endif
