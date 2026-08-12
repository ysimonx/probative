import Foundation

/// Collecte des blocs `timing` et `posture` — la part du noyau qui touche
/// l'appareil.
///
/// **Aucune permission n'est requise ici**, et c'est délibéré : sceller des
/// octets remis ne doit coûter ni caméra ni position. Ce qui exige une
/// autorisation relève de l'acquisition, donc du profil `capture`.
///
/// Rien n'est jugé : ces valeurs partent telles quelles au serveur
/// (invariant 1). Un client compromis peut toutes les mentir, et c'est
/// précisément pourquoi elles ne pèsent presque rien dans la notation.
public enum DeviceState {

    /// Les trois horloges au moment de l'appel.
    ///
    /// **`automaticTime` est toujours omis sur iOS**, et ce n'est pas un
    /// oubli : le système n'expose aucune interface publique disant si
    /// l'heure est réglée automatiquement. Android l'expose
    /// (`Settings.Global.AUTO_TIME`), iOS non. L'asymétrie est absorbée par
    /// le format, dont le label 4 est optionnel — c'est exactement ce que
    /// prévoit l'invariant 4 : les plateformes atteignent le même niveau par
    /// des chemins différents, et aucun champ obligatoire n'est propre à
    /// l'une d'elles.
    ///
    /// Deviner la valeur serait pire que l'omettre : le serveur ne saurait
    /// pas distinguer une mesure d'une supposition.
    public static func timing() -> Timing {
        let now = Date()
        let wallMs = Int64((now.timeIntervalSince1970 * 1000).rounded())
        return Timing(
            wallMs: wallMs,
            uptimeMs: Int64((ProcessInfo.processInfo.systemUptime * 1000).rounded()),
            // Décalage calculé pour l'instant courant, pas pour le fuseau « en
            // général » : un fuseau à heure d'été rendrait sinon une valeur
            // fausse la moitié de l'année.
            utcOffsetMinutes: TimeZone.current.secondsFromGMT(for: now) / 60,
            automaticTime: nil
        )
    }

    /// L'état déclaré de l'appareil. `appVersion` vient de l'intégrateur : le
    /// cœur ne connaît pas le bundle de l'application qui l'embarque.
    public static func posture(appVersion: String) -> Posture {
        Posture(
            platform: "ios",
            osVersion: osVersion(),
            appVersion: appVersion,
            debuggerAttached: debuggerAttached(),
            simulatorSuspected: simulatorSuspected,
            jailbreakSuspected: jailbreakSuspected()
        )
    }

    private static func osVersion() -> String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return v.patchVersion == 0
            ? "\(v.majorVersion).\(v.minorVersion)"
            : "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    private static var simulatorSuspected: Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            return false
        #endif
    }

    /// Débogueur attaché — l'indicateur `P_TRACED` du noyau, lu par `sysctl`.
    ///
    /// Contrairement à Android, il n'existe pas d'appel dédié : c'est la
    /// méthode documentée par Apple (QA1361). Elle ne détecte qu'un débogueur
    /// attaché au processus, ce qui est exactement ce que le champ décrit.
    private static func debuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let code = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        // Un `sysctl` en échec ne prouve rien : on ne déclare pas l'absence de
        // débogueur, on déclare ce qu'on a lu — et faute de lecture, `false`
        // est ici la seule valeur possible puisque le champ est obligatoire.
        // C'est la limite du caractère déclaratif de `posture`, pas un trou de
        // sécurité : le serveur ne fonde rien de décisif sur ce booléen.
        guard code == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Heuristiques de jailbreak (label 9), **mesurées sur appareil seulement**.
    ///
    /// Sur simulateur et sur macOS, le système de fichiers est celui du Mac :
    /// `/bin/bash` et `/usr/sbin/sshd` y existent normalement, et les mêmes
    /// tests y crieraient au jailbreak sur une machine parfaitement saine. On
    /// rend donc `nil` — « non mesuré » — plutôt qu'un faux positif, et le
    /// champ est omis de la charge utile.
    ///
    /// Volontairement grossier, comme la détection d'émulateur côté Android :
    /// un jailbreak déterminé masque ces traces. La défense est App Attest,
    /// qui répond sans que l'appareil ait son mot à dire ; ce booléen ne sert
    /// qu'à rendre lisible le cas ordinaire.
    private static func jailbreakSuspected() -> Bool? {
        #if os(iOS) && !targetEnvironment(simulator)
            let traces = [
                "/Applications/Cydia.app",
                "/Applications/Sileo.app",
                "/Library/MobileSubstrate/MobileSubstrate.dylib",
                "/bin/bash",
                "/usr/sbin/sshd",
                "/etc/apt",
                "/private/var/lib/apt/",
            ]
            if traces.contains(where: { FileManager.default.fileExists(atPath: $0) }) {
                return true
            }
            // Écrire hors du bac à sable est le signe le moins contournable :
            // une application non jailbreakée n'en a jamais le droit.
            let sonde = "/private/probative-\(UUID().uuidString)"
            do {
                try "sonde".write(toFile: sonde, atomically: true, encoding: .utf8)
                try? FileManager.default.removeItem(atPath: sonde)
                return true
            } catch {
                return false
            }
        #else
            return nil
        #endif
    }
}
