# Spécification d'enveloppe de capture attestée — v0.1

**Statut : proposition, à geler après le spike d'attestation natif.**
Dérive du modèle de menace v0.2.

Préfixe de spécification : `probative/`. La valeur exacte du label 100 de l'en-tête
protégé est `probative/0.1` — arrêtée le 2026-08-11, voir §8 pour la politique de
version et §9 pour ce qui reste ouvert.

---

## 1. Vue d'ensemble

Le format repose sur deux échanges distincts. Les confondre est l'erreur classique.

### 1.1 Enrôlement — une fois par installation

L'appareil génère une paire de clés dans son composant matériel sécurisé, puis transmet au serveur la preuve que cette clé y réside réellement.

| | Android | iOS |
|---|---|---|
| Génération | Keystore, `setAttestationChallenge(nonce)`, StrongBox si disponible | `DCAppAttestService.generateKey()` |
| Preuve | Chaîne de certificats X.509 jusqu'à la racine Google Hardware Attestation | Objet d'attestation vérifié contre la racine Apple App Attest |
| Stocké par le serveur | Clé publique, niveau de sécurité, empreinte du binaire | Clé publique, `keyId`, **compteur d'assertion initial** |

À l'issue de l'enrôlement, le serveur détient une clé publique dont il sait qu'elle est non exportable et liée à une application authentique.

### 1.2 Capture — à chaque prise de vue

L'appareil produit une enveloppe `COSE_Sign1` signée par cette clé, accompagnée d'une preuve de fraîcheur.

**L'enrôlement prouve *à qui appartient la clé*. La capture prouve *que cette clé a signé ce contenu précis, maintenant*.**

---

## 2. Structure

L'enveloppe est un `COSE_Sign1` étiqueté (tag CBOR 18).

```cddl
probative-envelope = #6.18(COSE_Sign1)

COSE_Sign1 = [
  protected   : bstr .cbor header-protected,
  unprotected : header-unprotected,
  payload     : bstr .cbor capture-claims,
  signature   : bstr
]
```

### 2.1 En-tête protégé — couvert par la signature

```cddl
header-protected = {
  1   => -7,            ; alg : ES256
  4   => bstr,          ; kid : SHA-256 de la clé publique attestée
  100 => "probative/0.1",      ; version de spécification
  101 => tstr,          ; identifiant de déploiement (multi-tenant)
}
```

### 2.2 En-tête non protégé — non signé, mais auto-liant

```cddl
header-unprotected = {
  200 => freshness
}

freshness = {
  1 => "play-integrity" / "app-attest",
  2 => bstr,          ; jeton d'intégrité ou assertion, opaque
  ? 3 => uint,        ; compteur d'assertion (iOS uniquement)
}
```

L'absence de signature sur cet en-tête n'est pas une faiblesse : le jeton de fraîcheur se lie lui-même au contenu par la règle de §3. Le modifier invalide la vérification.

### 2.3 Charge utile

```cddl
capture-claims = {
  1   => bstr,              ; nonce serveur, brut
  2   => media,
  3   => position,
  4   => timing,
  5   => posture,
  ? 6 => [+ claim],         ; corroboration, extensible
  ? 7 => bstr,              ; chaînage : SHA-256 de l'enveloppe précédente
}
```

Le champ 7 reconstruit sur Android l'ordonnancement inviolable qu'iOS obtient gratuitement via le compteur d'assertion. Chaque enveloppe référence la précédente ; le serveur détecte tout trou ou toute réinsertion.

```cddl
media = {
  1 => "sha-256",
  2 => bstr,                ; empreinte des octets bruts du capteur
  3 => tstr,                ; type MIME
  4 => uint,                ; taille en octets
  5 => [uint, uint],        ; largeur, hauteur
  6 => uint,                ; latence capture → signature, en ms
}
```

> La latence du champ 6 est un signal de détection sous-estimé. Une capture légitime signe en quelques dizaines de millisecondes. Une injection par caméra virtuelle ou une manipulation intermédiaire allonge presque toujours ce délai.

```cddl
position = {
  1   => float64,           ; latitude WGS84
  2   => float64,           ; longitude WGS84
  3   => float32,           ; précision horizontale, mètres
  ? 4 => float32,           ; altitude ellipsoïdale, mètres
  ? 5 => float32,           ; précision verticale
  6   => "gnss" / "fused" / "network" / "unknown",
  7   => uint,              ; ancienneté du point au moment de la capture, ms
  ? 8 => uint,              ; nombre de satellites utilisés (Android)
}
```

Le champ 7 est essentiel : un point vieux de trente secondes ne prouve rien sur la position au déclenchement. Il doit être borné, pas simplement enregistré.

```cddl
timing = {
  1   => uint,              ; horloge murale, epoch ms
  2   => uint,              ; horloge monotone depuis démarrage, ms
  3   => int,               ; décalage UTC, minutes
  ? 4 => bool,              ; synchronisation automatique de l'heure active
}
```

```cddl
posture = {
  1   => "android" / "ios",
  2   => tstr,              ; version OS
  3   => tstr,              ; version applicative
  4   => bool,              ; débogueur attaché
  5   => bool,              ; émulateur ou simulateur suspecté
  ? 6 => bool,              ; mode développeur actif
  ? 7 => bool,              ; indicateur de position simulée   (Android)
  ? 8 => [* tstr],          ; paquets suspects détectés        (Android)
  ? 9 => bool,              ; heuristiques de jailbreak         (iOS)
}
```

Tous ces champs sont **déclaratifs et falsifiables**. Ils ne prouvent rien seuls : leur valeur tient à leur incohérence avec l'attestation. Un appareil qui déclare `posture.4 = false` alors que Play Integrity échoue se contredit lui-même, et c'est cette contradiction qui est exploitable.

### 2.4 Réclamations de corroboration

```cddl
claim = {
  1 => tstr,                ; type
  2 => tstr,                ; identifiant du capteur ou fournisseur
  3 => uint,                ; horodatage monotone de la mesure, ms
  4 => any,                 ; mesure, spécifique au type
}
```

Aucun indice de confiance n'est transporté. Le client mesure, le serveur juge.

Types définis en v0.1 :

| Type | Mesure | Android | iOS |
|---|---|---|---|
| `baro` | pression en hPa | `TYPE_PRESSURE` | `CMAltimeter` |
| `baro-alt` | altitude barométrique relative, m | `CMAltimeter` | `CMAltimeter` |
| `motion` | fenêtre de 10 s : `[[t, ax, ay, az], …]` | `TYPE_ACCELEROMETER` | `CMMotionManager` |
| `steps` | pas cumulés sur la fenêtre | `TYPE_STEP_COUNTER` | `CMPedometer` |
| `activity` | énumération : `still` / `walking` / `driving` | Activity Recognition | `CMMotionActivity` |

Un vérificateur **doit ignorer silencieusement** tout type inconnu. C'est ce qui rend l'ajout des réclamations radio en v0.2 non cassant.

---

## 3. Règles de liaison — le cœur du format

Trois règles empêchent de recombiner des éléments authentiques pris séparément. Ce sont les seules qui comptent vraiment.

### R1 — Liaison de la fraîcheur au contenu

Le défi soumis au service d'attestation de plateforme **doit** valoir exactement :

```
challenge = SHA-256( payload_bytes || nonce )
```

Android : ce condensat est le `requestHash` de la requête Play Integrity.
iOS : ce condensat est le `clientDataHash` passé à `generateAssertion`.

Sans R1, un attaquant obtient un jeton d'intégrité valide sur un appareil sain, puis l'attache à une charge utile forgée. R1 rend l'opération impossible : le jeton n'est valide que pour ce contenu-là.

### R2 — Liaison de la signature à la clé attestée

La signature `COSE_Sign1` doit se vérifier avec la clé publique enregistrée à l'enrôlement, identifiée par le `kid` de l'en-tête protégé. Aucune clé transmise dans l'enveloppe n'est acceptée.

### R3 — Unicité du nonce

Le nonce est émis par le serveur, à usage unique, avec une durée de validité explicite. Un nonce consommé est refusé définitivement.

En mode hors ligne, le serveur pré-délivre un lot de nonces à durée de vie étendue. Toute enveloppe utilisant un nonce pré-délivré est plafonnée à `DEGRADED`.

---

## 4. Résultat de vérification

Le vérificateur ne retourne pas un score global mais une structure par propriété, conformément au modèle de menace §6.

```json
{
  "spec": "probative/0.1",
  "level": "STANDARD",
  "properties": {
    "origin":    { "grade": "B", "evidence": ["play-integrity:PLAY_RECOGNIZED", "raw-hash-match"] },
    "position":  { "grade": "A", "evidence": ["gnss", "baro-consistent", "motion-consistent"] },
    "time":      { "grade": "B", "evidence": ["nonce-fresh", "monotonic-consistent"] },
    "integrity": { "grade": "A", "evidence": ["cose-valid", "key-attested-strongbox"] }
  },
  "flags": ["BARO_ABSENT"],
  "level_reason": "origin capped at B: screen-capture detection not implemented in v0.1"
}
```

Le champ `level_reason` est obligatoire. Un vérificateur qui refuse sans dire pourquoi est inexploitable en support, et vous le paierez en tickets.

---

## 5. Ordre de vérification serveur

L'ordre importe : on écarte au plus vite et au moins cher.

1. Version de spécification connue → sinon `REJECTED`
2. Nonce connu, non consommé, non expiré → sinon `REJECTED`
3. Signature `COSE_Sign1` valide sous la clé du `kid` → sinon `REJECTED`
4. Recalcul de R1, comparaison au défi contenu dans le jeton → sinon `REJECTED`
5. Validation du jeton d'intégrité auprès de Google ou Apple → sinon `UNTRUSTED`
6. iOS : compteur d'assertion strictement croissant → sinon `REJECTED`
7. Android : chaînage cohérent avec la dernière enveloppe connue → sinon signalement
8. Empreinte de l'image recalculée sur les octets reçus → sinon `REJECTED`
9. Cohérence de posture, position, corroboration → détermination des grades
10. Nonce marqué comme consommé

Les étapes 1 à 4 sont locales et coûtent une milliseconde. L'étape 5 est un appel réseau : elle vient après, jamais avant.

---

## 6. Ce qui n'est délibérément pas dans le format

- **Aucun champ métier.** Pas de référence de dossier, pas de site, pas d'opérateur. Le contexte applicatif est lié par le nonce, côté serveur. C'est ce qui rend la bibliothèque réutilisable et évite qu'elle traîne du vocabulaire client.
- **Aucune donnée de tiers.** Les réclamations radio de la v0.2 n'entreront qu'avec un condensat salé par déploiement.
- **Aucune identité d'utilisateur.** Le format prouve l'appareil, jamais la personne.
- **L'image elle-même.** Seule son empreinte circule dans l'enveloppe. Le média est transféré séparément, ce qui permet de rejeter une capture avant d'avoir dépensé la bande passante.

---

## 7. Sérialisation

CBOR canonique, RFC 8949 §4.2.1, sans exception. Deux implémentations doivent produire des octets identiques pour une même charge utile — sinon la signature ne se vérifie pas.

Type MIME proposé : `application/vnd.probative+cose`
Extension de fichier : `.prbv`

---

## 8. Politique de version

`probative/MAJEUR.MINEUR`. Une version mineure ajoute des réclamations ou des champs optionnels ; un vérificateur d'une version mineure inférieure doit rester capable de valider les quatre propriétés. Une version majeure change les règles de liaison de §3 — c'est le seul motif légitime.

Un vérificateur accepte les versions mineures qu'il ne connaît pas et signale `UNKNOWN_CLAIMS` sans dégrader le niveau.

---

## 9. Décisions ouvertes

| Sujet | Options | À trancher |
|---|---|---|
| Chaînage Android | Chaîne de hachage locale, ou compteur monotone stocké dans le Keystore | Après le spike |
| Fenêtre inertielle | 10 s fixes, ou adaptative selon l'activité détectée | Après mesure de l'impact sur la taille d'enveloppe |
| Alignement C2PA | Enveloppe native puis passerelle, ou manifeste C2PA dès le départ | v0.3 |

### Arrêtées

Conservées ici pour que le motif reste lisible après le gel de la spécification.

| Sujet | Décision | Date |
|---|---|---|
| Nom de projet | `probative` — au sens juridique, « qui tend à prouver » : la pièce a une valeur probante, appréciée par un tiers, jamais autoproclamée. Libre sur PyPI, npm et pub.dev à cette date. | 2026-08-11 |
| Préfixe de spécification | `probative/` — le label 100 vaut `probative/0.1`. Auto-descriptif au prix de 7 octets : qui inspecte des octets inconnus peut retrouver la spécification. | 2026-08-11 |
| Extension et type MIME | `.prbv`, `application/vnd.probative+cose` | 2026-08-11 |
