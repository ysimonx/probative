#!/usr/bin/env bash
# Recree les liens vers les secrets de ce poste. Aucun secret n'est ici :
# les fichiers reels vivent hors du depot, seuls les liens y entrent — et
# .gitignore les couvre tous les deux.
#
# A rejouer apres un clone, ou quand le repertoire de secrets bouge.
set -euo pipefail

SECRETS="${PROBATIVE_SECRETS:-$HOME/Documents/secrets/probative}"
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

chmod 700 "$SECRETS"

# --- Compte de service Google, lu par le verificateur a la racine ---------
# Le nom du fichier porte l'identifiant de la cle, donc il varie : on prend
# le seul JSON de compte de service present.
CLE_SERVICE="$(ls "$SECRETS"/probative-*.json | head -1)"
chmod 600 "$CLE_SERVICE"
ln -sfn "$CLE_SERVICE" "$RACINE/service-account.json"

# --- Cle de televersement Play, lue par Gradle -----------------------------
# Dans mobile/android/ et NON dans ~/.gradle/gradle.properties : ce dernier
# vaudrait pour tous les projets Android de la machine, alors que cette cle
# n'appartient qu'a probative.
chmod 600 "$SECRETS/keystore.properties" "$SECRETS/upload-keystore.jks"
ln -sfn "$SECRETS/keystore.properties" "$RACINE/mobile/android/keystore.properties"

# --- Fichier d'environnement, lu par le serveur de developpement ----------
# CE FICHIER NE CONTIENT AUCUN SECRET : une empreinte de certificat est
# publique, n'importe qui possedant l'application peut l'extraire d'un APK
# livre. Le dire secret aurait un effet concret -- on hesiterait a le poser
# dans une CI ou a le montrer dans un ticket, alors que c'est precisement ce
# qu'on doit pouvoir faire d'une configuration.
#
# Les vrais secrets sont les deux fichiers ci-dessus, et ils n'y entrent
# jamais. Voir .env.example, versionne, qui documente chaque reglage.
chmod 644 "$SECRETS/env"
ln -sfn "$SECRETS/env" "$RACINE/.env"

echo "liens en place :"
ls -l "$RACINE/service-account.json" \
      "$RACINE/mobile/android/keystore.properties" \
      "$RACINE/.env"
