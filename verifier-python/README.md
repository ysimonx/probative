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

Boucle complète avec `curl` (les octets binaires transitent en base64) :

```bash
# 1. Enrôler une clé publique P-256 (X9.62 non compressée, 65 octets)
curl -s http://127.0.0.1:8765/enroll -d '{
  "public_key_x962_b64": "'$PUBKEY_B64'", "platform": "android"
}'
# → {"kid_b64": "...", "kid_hex": "..."}

# 2. Obtenir un nonce
curl -s http://127.0.0.1:8765/nonce -d '{}'
# → {"nonce_b64": "...", "ttl_ms": 120000, "offline": false}

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
