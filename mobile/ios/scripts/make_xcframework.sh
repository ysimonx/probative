#!/usr/bin/env bash
# Produit l'artefact XCFramework autonome du cœur iOS (ADR-0003).
#
# Recette — validée sur Xcode 26 : l'archivage xcodebuild d'un package
# SwiftPM ne place aucun framework dans l'archive (seul un .o en sort).
# On assemble donc l'artefact à partir des produits de build :
# bibliothèque statique via libtool, puis swiftmodule — qui contient les
# .swiftinterface, l'évolution de bibliothèque étant active — posé à
# côté de la .a pour que -create-xcframework l'embarque de lui-même.
set -euo pipefail
cd "$(dirname "$0")/.."

SCHEME=AttestedCaptureCore
DERIVED=build/xcframework-dd
STAGING=build/xcframework-staging
OUT=build/AttestedCaptureCore.xcframework

rm -rf "$DERIVED" "$STAGING" "$OUT"

for dest in "generic/platform=iOS" "generic/platform=iOS Simulator"; do
    xcodebuild build \
        -scheme "$SCHEME" \
        -configuration Release \
        -destination "$dest" \
        -derivedDataPath "$DERIVED" \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
        -quiet
done

CREATE_ARGS=()
for products in "$DERIVED"/Build/Products/Release-*; do
    plat=$(basename "$products")
    mkdir -p "$STAGING/$plat"
    libtool -static -o "$STAGING/$plat/lib$SCHEME.a" "$products/$SCHEME.o"
    cp -R "$products/$SCHEME.swiftmodule" "$STAGING/$plat/"
    CREATE_ARGS+=(-library "$STAGING/$plat/lib$SCHEME.a")
done

xcodebuild -create-xcframework "${CREATE_ARGS[@]}" -output "$OUT"
echo "artefact : $OUT"
