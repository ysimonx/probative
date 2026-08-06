// swift-tools-version: 5.9
import PackageDescription

// Cœur natif iOS : bibliothèque autonome, sans dépendance à un framework
// applicatif (ADR-0003). macOS est déclaré uniquement pour exécuter les
// tests sur l'hôte — les vecteurs d'or se vérifient sans appareil.
let package = Package(
    name: "AttestedCaptureCore",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "AttestedCaptureCore", targets: ["AttestedCaptureCore"])
    ],
    targets: [
        .target(name: "AttestedCaptureCore"),
        .testTarget(
            name: "AttestedCaptureCoreTests",
            dependencies: ["AttestedCaptureCore"]
        ),
    ]
)
