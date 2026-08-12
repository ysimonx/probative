import Foundation

/// Client des trois routes du serveur de développement
/// (`python -m probative.devserver`).
///
/// Il vit dans la démonstration et non dans le cœur, à dessein : le cœur ne
/// doit connaître aucun protocole de transport. Un intégrateur envoie
/// l'enveloppe par où il veut — le verdict ne dépend jamais du canal
/// (invariant 7), et l'enveloppe s'authentifie par elle-même.
///
/// **Aucun équivalent d'`adb reverse` n'existe sur iOS** : l'appareil ne voit
/// pas la boucle locale du Mac, même relié en USB. Il faut donc une adresse
/// de réseau local, les deux machines sur le même Wi-Fi, et le serveur lancé
/// avec `--host 0.0.0.0`. L'adresse arrive par l'`Info.plist`, engendré par
/// `scripts/make_demo_project.rb` — c'est une donnée de poste, pas du code.
struct DevServer {

    enum Failure: Error, CustomStringConvertible {
        case refused(status: Int, detail: String)
        case transport(String)

        var description: String {
            switch self {
            case .refused(let status, let detail): return "HTTP \(status) — \(detail)"
            case .transport(let message): return "transport — \(message)"
            }
        }
    }

    let baseURL: URL

    /// Adresse déclarée dans l'`Info.plist`. Absente, c'est une faute de
    /// génération du projet, pas un cas d'exécution : on le dit franchement.
    static func fromBundle() -> DevServer? {
        guard
            let raw = Bundle.main.object(forInfoDictionaryKey: "ProbativeDevServer") as? String,
            let url = URL(string: raw)
        else { return nil }
        return DevServer(baseURL: url)
    }

    /// Enrôlement : la clé de signature d'enveloppe, **et** l'attestation App
    /// Attest qui établit l'appareil.
    ///
    /// Les deux clés sont distinctes et c'est le piège qui bloque net —
    /// `publicKeyX962` désigne la clé Secure Enclave du format, `keyId` la
    /// clé App Attest, incapable de signer autre chose qu'une assertion.
    func enroll(
        publicKeyX962: Data,
        keyId: Data,
        attestation: Data,
        challenge: Data
    ) async throws -> [String: Any] {
        try await post("/enroll", [
            "public_key_x962_b64": publicKeyX962.base64EncodedString(),
            "platform": "ios",
            "attestation_b64": attestation.base64EncodedString(),
            "key_id_b64": keyId.base64EncodedString(),
            "challenge_b64": challenge.base64EncodedString(),
        ])
    }

    /// Nonce, émis **pour un profil**. La réponse porte ce profil : c'est lui
    /// que l'enveloppe doit déclarer, et non celui que le client aurait choisi.
    func nonce(kid: Data, profile: String) async throws -> [String: Any] {
        try await post("/nonce", [
            "kid_b64": kid.base64EncodedString(),
            "profile": profile,
        ])
    }

    /// Vérification. Les octets du média accompagnent l'enveloppe : sans eux,
    /// le serveur ne peut pas recalculer l'empreinte de `media[2]` — il ne lui
    /// resterait que la parole du client sur ce qu'il a scellé.
    func verify(envelope: Data, media: Data) async throws -> [String: Any] {
        try await post("/verify", [
            "envelope_b64": envelope.base64EncodedString(),
            "media_b64": media.base64EncodedString(),
        ])
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        request.timeoutInterval = 30

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            // Distinguer le transport du refus : sur iOS, une permission
            // « réseau local » refusée se présente comme une erreur réseau
            // ordinaire, et l'attribuer au serveur enverrait chercher la
            // panne du mauvais côté.
            throw Failure.transport((error as NSError).localizedDescription)
        }

        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else {
            // Le corps porte le motif du refus, seul contenu exploitable :
            // un code seul n'apprend rien.
            throw Failure.refused(
                status: status,
                detail: String(data: data, encoding: .utf8) ?? "corps illisible"
            )
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.transport("réponse JSON inattendue")
        }
        return json
    }
}
