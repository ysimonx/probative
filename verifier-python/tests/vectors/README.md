# Vecteurs d'or

Octets de référence pour les encodeurs CBOR/COSE natifs (Kotlin, Swift).
Générés par `tools/gen_vectors.py` à partir de `tests/vectors.py` —
**ne pas éditer à la main**. Le test `test_vectors.py` compare ces
fichiers à une régénération : toute dérive casse le test.

Un cœur natif est conforme quand, pour les entrées du `manifest.json`,
il reproduit **octet à octet** `payload.cbor`, `protected.cbor`,
`sig_structure.cbor` et `challenge.bin`. L'enveloppe complète
(`envelope.prbv`) n'est *pas* reproductible sur appareil : sa signature
est ECDSA déterministe (RFC 6979), alors que Keystore et Secure Enclave
signent en ECDSA aléatoire. Elle sert de référence structurelle et de
garde de régression côté Python.

> La clé privée du `manifest.json` est une **clé logicielle de test**,
> dérivée d'une étiquette publique. Elle ne protège rien, n'existe sur
> aucun appareil, et n'est pas du matériel cryptographique réel au sens
> du `.gitignore`.

## Fichiers

| Fichier | Contenu |
|---|---|
| `{n}.payload.cbor` | Charge utile `capture-claims`, CBOR canonique |
| `{n}.protected.cbor` | En-tête protégé encodé (`bstr .cbor`) |
| `{n}.sig_structure.cbor` | `Sig_structure` COSE — les octets réellement signés |
| `{n}.challenge.bin` | Défi R1 : `SHA-256(payload_bytes ‖ nonce)`, 32 octets |
| `{n}.envelope.prbv` | Enveloppe `COSE_Sign1` complète, tag 18 |
| `manifest.json` | Toutes les entrées, en hexadécimal |

Trois jeux, dont le `manifest.json` donne la plateforme et le profil :

| Jeu | Profil | Ce qu'il couvre en propre |
|---|---|---|
| `android` | `capture` | chaînage `payload[7]`, posture 6/7/8 |
| `ios` | `capture` | compteur d'assertion `freshness[3]`, posture 9 |
| `core` | `core` | ni `position`, ni `media[5]`, ni corroboration |

Le jeu `core` n'est pas décoratif : c'est la seule forme dont la charge
utile ne suppose ni capteur ni lieu. Un encodeur natif qui aurait câblé
`position` en dur passerait les deux premiers jeux et échouerait sur
celui-ci.

## Pièges d'encodage — ce que les vecteurs attrapent

- **Ordre canonique des clés de map** (RFC 8949 §4.2.1) : tri par octets
  d'encodage croissants. Pour les clés entières positives du format,
  cela coïncide avec l'ordre numérique — mais c'est bien l'encodage qui
  fait foi, pas la valeur. Attention : cbor2 trie « longueur d'abord »
  (RFC 7049) ; les deux ordres divergent dès qu'une clé négative
  apparaît (`{24, -1}` : la RFC 8949 met `24` en premier, cbor2 met
  `-1`). La spec §7 impose donc des clés **non signées**, où les deux
  ordres coïncident.
- **Flottants en forme la plus courte qui préserve la valeur.** Les
  trois largeurs coexistent dans un même vecteur : `8.0` s'encode en
  **float16** (`f9 48 00`), `48.2973` en float64. Un encodeur qui émet
  systématiquement du float64 produira des octets différents — et une
  signature invalide. L'encodage demi-précision doit être implémenté.
- **Entiers en forme la plus courte** : `100` → `18 64`, jamais
  `19 00 64`.
- **`Sig_structure`** (RFC 8152 §4.4) :
  `["Signature1", protected_bytes, b"", payload_bytes]` — contexte
  exact, `external_aad` vide, en-tête protégé et charge utile en
  `bstr`, pas re-décodés.
- **Signature brute `r ‖ s`**, 64 octets, chaque moitié cadrée à
  32 octets — pas de DER. Keystore et Secure Enclave rendent du DER :
  la conversion est à la charge du cœur natif.
- **Tag CBOR 18** sur l'enveloppe complète (`d2` en tête).
- **`kid`** = SHA-256 de la clé publique X9.62 non compressée
  (`04 ‖ X ‖ Y`, 65 octets).
- **Défi R1** calculé sur les octets *encodés* de la charge utile —
  ceux qui partent dans l'enveloppe — concaténés au nonce brut.
- Le jeton de fraîcheur des vecteurs vaut `b"NULLTOKEN:" ‖ challenge` :
  c'est le substitut accepté par `NullAttestationVerifier`, jamais un
  vrai jeton Play Integrity ou App Attest.
