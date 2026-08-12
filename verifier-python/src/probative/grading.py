"""Attribution des grades par propriété.

Chaque propriété est notée indépendamment, puis le niveau global vaut
celui de la propriété la plus faible : une chaîne vaut son maillon le
plus faible.

Les seuils de ce module sont des points de départ, pas des vérités. Ils
devront être recalibrés sur données réelles après le spike — c'est
attendu, et c'est la raison pour laquelle ils sont tous regroupés ici en
constantes plutôt que dispersés dans le code.
"""

from __future__ import annotations

from .attestation import AttestationOutcome, DeviceIntegrity
from .errors import MalformedEnvelope
from .model import (
    CaptureClaims,
    Grade,
    Level,
    Platform,
    Profile,
    Property,
    PropertyResult,
)

# --- Seuils, à recalibrer sur données réelles ---------------------------

MAX_FIX_AGE_MS = 15_000        # au-delà, le point ne prouve rien sur l'instant
MAX_H_ACCURACY_M = 50.0        # au-delà, la position est trop floue
MIN_H_ACCURACY_M = 1.0         # en deçà, précision anormalement parfaite
MAX_SIGN_LATENCY_MS = 3_000    # au-delà, une manipulation intermédiaire est probable
MAX_CLOCK_SKEW_MS = 300_000    # écart toléré entre horloge murale et horloge serveur
BARO_ALT_TOLERANCE_M = 60.0    # écart toléré entre altitude GNSS et barométrique

# Politique de distribution, et non conséquence du modèle de menace.
#
# Sur Android, « binaire reconnu » signifie très précisément *ce binaire est
# celui que Google Play distribue*. Une application diffusée hors Play ne
# l'obtient jamais, même saine et même déclarée en Play Console. Mettre F
# revient donc à refuser toute diffusion hors magasin — ce qui est un choix,
# pas une fatalité. iOS n'a pas cette limite : App Attest ignore le canal.
#
# Trois options restent ouvertes (modèle de menace §7, limite 7) : conserver
# le refus, dégrader d'un cran, ou en faire un réglage par déploiement. À
# trancher quand la phase B aura montré ce que le jeton déchiffré contient.
# La constante existe pour que ce jour-là il n'y ait qu'une ligne à changer.
UNRECOGNIZED_APP_GRADE = Grade.F

# Plafond structurel du profil capture : la recapture analogique n'est pas
# détectée en v0.1. Photographier un écran et enregistrer un haut-parleur
# qui rejoue un enregistrement sont la même attaque — position
# authentique, attestation valide, contenu faux. Le plafond appartient
# donc au profil tout entier, et non à un médium particulier.
#
# Le noyau n'est pas concerné : il n'affirme rien sur le monde physique,
# donc rien qu'un capteur puisse être trompé d'acquérir.
RECAPTURE_CAP = Grade.B
RECAPTURE_CAP_REASON = (
    "origin plafonné à B : détection de recapture analogique non implémentée en v0.1"
)


def grade_integrity(att: AttestationOutcome, hardware_backed: bool) -> PropertyResult:
    r = PropertyResult(Grade.A, evidence=["cose-valid"])
    if hardware_backed:
        r.evidence.append("key-attested-hardware")
    else:
        r.grade = Grade.C
        r.notes.append("clé non adossée au matériel")
    return r


def grade_origin(
    claims: CaptureClaims, att: AttestationOutcome, profile: Profile
) -> PropertyResult:
    """Provenance des octets — et, pour le profil capture, du signal.

    La part noyau — application reconnue, intégrité, latence — vaut pour
    tout payload et peut atteindre A. Le plafond de recapture ne
    s'applique qu'au profil `capture`, qui seul prétend dire quelque
    chose du monde physique.
    """
    r = PropertyResult(Grade.A, evidence=["raw-hash-match"])

    if att.app_recognized:
        r.evidence.append("app-recognized")
    else:
        r.grade = UNRECOGNIZED_APP_GRADE
        r.notes.append(
            "binaire non reconnu par le fournisseur d'attestation — reconditionné, "
            "ou simplement distribué hors du magasin officiel"
        )
        return r

    if att.integrity is DeviceIntegrity.FAILED:
        r.grade = Grade.F
        r.notes.append("intégrité de l'appareil en échec")
        return r

    if claims.media.sign_latency_ms > MAX_SIGN_LATENCY_MS:
        r.grade = Grade.C
        r.notes.append(
            f"latence payload→signature anormale : {claims.media.sign_latency_ms} ms"
        )

    if profile is Profile.CAPTURE:
        r.grade = min(r.grade, RECAPTURE_CAP, key=_grade_rank)
        r.notes.append(RECAPTURE_CAP_REASON)
    return r


def grade_position(claims: CaptureClaims, att: AttestationOutcome) -> PropertyResult:
    p = claims.position
    if p is None:
        # Garanti par `profiles.require_fields` : seuls les profils qui
        # exigent une position font noter cette propriété. Le garde reste,
        # parce qu'un profil futur mal câblé doit échouer bruyamment.
        raise MalformedEnvelope("position absente alors que le profil l'exige")
    r = PropertyResult(Grade.A, evidence=[p.provider])

    if claims.posture.mock_location is True:
        r.grade = Grade.F
        r.notes.append("position simulée déclarée par le système")
        return r

    if att.integrity is DeviceIntegrity.FAILED:
        r.grade = Grade.F
        r.notes.append("intégrité en échec : aucun signal de position n'est crédible")
        return r

    if p.fix_age_ms > MAX_FIX_AGE_MS:
        r.grade = Grade.C
        r.notes.append(f"point de position vieux de {p.fix_age_ms} ms au déclenchement")

    if p.h_accuracy > MAX_H_ACCURACY_M:
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append(f"précision horizontale insuffisante : {p.h_accuracy} m")
    elif p.h_accuracy < MIN_H_ACCURACY_M:
        # Une précision trop parfaite est un marqueur classique de simulation.
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append(f"précision anormalement parfaite : {p.h_accuracy} m")

    # Corroboration barométrique : le signal le plus rentable des deux
    # plateformes, et celui qu'un simulateur GPS ne falsifie jamais.
    baro = claims.claim("baro-alt")
    if baro is not None and p.altitude is not None:
        try:
            delta = abs(float(baro.value) - float(p.altitude))
        except (TypeError, ValueError):
            r.notes.append("réclamation baro-alt illisible")
        else:
            if delta <= BARO_ALT_TOLERANCE_M:
                r.evidence.append("baro-consistent")
            else:
                r.grade = min(r.grade, Grade.C, key=_grade_rank)
                r.notes.append(f"incohérence altimétrique : {delta:.0f} m d'écart")
    else:
        r.notes.append("corroboration barométrique absente")

    if claims.claim("motion") is not None or claims.claim("steps") is not None:
        r.evidence.append("motion-present")

    # Sur iOS, l'absence d'indicateur de mock est structurelle. On ne la
    # compte pas comme une lacune, mais on exige la corroboration inertielle.
    if claims.posture.platform is Platform.IOS and "motion-present" not in r.evidence:
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append(
            "iOS sans corroboration inertielle : aucun contrepoids à l'absence "
            "d'indicateur de position simulée"
        )

    return r


def grade_time(
    claims: CaptureClaims,
    att: AttestationOutcome,
    server_now_ms: int,
    offline: bool,
    counter_verified: bool,
    chain_verified: bool,
) -> PropertyResult:
    r = PropertyResult(Grade.B, evidence=["nonce-fresh"])

    skew = abs(claims.timing.wall_ms - server_now_ms)
    if skew <= MAX_CLOCK_SKEW_MS:
        r.evidence.append("clock-consistent")
    else:
        r.grade = Grade.C
        r.notes.append(f"écart d'horloge de {skew // 1000} s avec le serveur")

    if claims.timing.auto_time is False:
        r.notes.append("synchronisation automatique de l'heure désactivée")

    # L'ordonnancement vérifié fait passer time en A. iOS l'obtient
    # gratuitement via le compteur d'assertion, Android par chaînage.
    if counter_verified:
        r.grade = Grade.A
        r.evidence.append("assertion-counter-monotonic")
    elif chain_verified:
        r.grade = Grade.A
        r.evidence.append("envelope-chain-verified")

    if offline:
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append("nonce pré-délivré : capture hors ligne")

    return r


_RANK = {Grade.A: 3, Grade.B: 2, Grade.C: 1, Grade.F: 0}


def _grade_rank(g: Grade) -> int:
    return _RANK[g]


def overall_level(
    properties: dict[Property, PropertyResult], offline: bool
) -> tuple[Level, str]:
    """Le niveau global est celui de la propriété la plus faible."""
    weakest_prop, weakest = min(
        properties.items(), key=lambda kv: _grade_rank(kv[1].grade)
    )
    g = weakest.grade

    if g is Grade.F:
        return Level.UNTRUSTED, f"{weakest_prop.value} en échec : " + "; ".join(
            weakest.notes
        )
    if offline:
        return Level.DEGRADED, "capture hors ligne sur nonce pré-délivré"
    if g is Grade.C:
        return Level.DEGRADED, f"{weakest_prop.value} dégradé : " + "; ".join(
            weakest.notes
        )
    if g is Grade.B:
        reason = "; ".join(weakest.notes) or f"{weakest_prop.value} au grade B"
        return Level.STANDARD, reason
    return Level.STRONG, "toutes les propriétés au grade A"
