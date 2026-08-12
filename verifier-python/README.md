# probative (vérificateur Python)

Vérificateur serveur d'enveloppes de capture photo géolocalisée attestée,
spécification `probative/0.1`.

Le client collecte et signe des preuves, le serveur juge. Le code client est
intégralement considéré comme hostile : aucune décision de validité n'est prise
sur l'appareil, et l'API n'expose jamais de booléen de confiance.

Le dépôt complet — modèle de menace, spécification d'enveloppe, clients mobiles —
se trouve un niveau au-dessus.

## Serveur de développement

Cible HTTP du spike natif : trois routes JSON, états en mémoire, substitut
d'attestation. Jamais en production.

```bash
.venv/bin/python -m probative.devserver          # http://127.0.0.1:8765
```

### Configuration

Les réglages propres à un déploiement se donnent dans un `.env` à la racine du
dépôt — `cp .env.example .env`, puis compléter. Le fichier est ignoré par git ;
l'environnement réel prime sur lui. Aucun secret n'y entre : la clé de compte de
service et la clé de téléversement Play vivent hors du dépôt (`install.sh`).

Le serveur annonce au démarrage ce qu'il a chargé, et ce qu'il n'a pas :

```
Aucune empreinte déclarée (PROBATIVE_TRUSTED_APP_CERTS vide) : un binaire non
reconnu par le magasin sera noté sans distinction d'origine.
```

Boucle complète avec `curl` (les octets binaires transitent en base64) :

```bash
# 1. Enrôler une clé publique P-256 (X9.62 non compressée, 65 octets)
#    Sans attestation, la clé est acceptée SUR PAROLE : c'est le mode
#    dégradé, et la réponse le dit (attested: false).
#
#    iOS      : joindre attestation_b64, challenge_b64 et key_id_b64 — la
#               chaîne App Attest est validée jusqu'à la racine Apple.
#    Android  : joindre attestation_chain_b64 (liste, feuille en tête) et
#               challenge_b64 — la chaîne est validée jusqu'aux racines
#               publiées par Google, et le niveau de sécurité en est tiré.
#               Le drapeau hardware_backed du corps est alors ignoré.
curl -s http://127.0.0.1:8765/enroll -d '{
  "public_key_x962_b64": "'$PUBKEY_B64'", "platform": "android",
  "attestation_chain_b64": ["'$FEUILLE_B64'", "'$RACINE_B64'"],
  "challenge_b64": "'$DEFI_B64'"
}'
# → {"kid_b64": "...", "kid_hex": "...", "attested": true}

# 2. Obtenir un nonce — émis POUR cet appareil, et inutilisable par un autre
#    (règle R3). Un kid non enrôlé est refusé.
curl -s http://127.0.0.1:8765/nonce -d '{"kid_b64": "'$KID_B64'"}'
# → {"nonce_b64": "...", "ttl_ms": 120000, "offline": false, "profile": "capture"}

# 3. Capturer, signer, puis soumettre l'enveloppe et le média
curl -s http://127.0.0.1:8765/verify -d '{
  "envelope_b64": "'$(base64 < capture.prbv)'",
  "media_b64":    "'$(base64 < photo.jpg)'"
}'
# → résultat structuré : level, grades par propriété, level_reason, flags
```

## Vecteurs d'or

`tests/vectors/` fige les octets que les encodeurs CBOR/COSE natifs doivent
reproduire à l'identique. Régénération : `python tools/gen_vectors.py` depuis la
racine du dépôt. Voir `tests/vectors/README.md`.

## Licence

Apache-2.0.
