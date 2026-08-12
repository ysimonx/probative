"""Attribution des grades par propriété.

Chaque propriété est notée indépendamment, puis le niveau global vaut
celui de la propriété la plus faible : une chaîne vaut son maillon le
plus faible.

Les seuils de ce module sont des points de départ, pas des vérités. Ils
devront être recalibrés sur données réelles après le spike — c'est
attendu, et c'est la raison pour laquelle ils sont tous regroupés dans
`GradingPolicy` plutôt que dispersés dans le code.

Deux règles départagent ce qui se règle de ce qui se tranche :

  * **ce qui change le format se tranche, ce qui change l'exploitation se
    configure** — on ne se configure pas hors d'une décision de format ;
  * **une option peut resserrer, jamais desserrer un angle mort assumé.**
    D'où `RECAPTURE_CAP`, qui reste une constante en dur : le rendre
    réglable permettrait à un déploiement de revendiquer `STRONG` sur des
    captures sans avoir implémenté la détection.

Enfin, un verdict calculé sous une politique modifiée **n'est pas
comparable** à un verdict calculé sous celle par défaut : `STANDARD` ne
voudrait plus dire la même chose d'un déploiement à l'autre. Le résultat
porte donc les écarts appliqués — même raisonnement que pour le profil en
ADR-0005 : lire le niveau sans regarder les règles, c'est ignorer selon
quoi il a été calculé.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

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


@dataclass(frozen=True)
class GradingPolicy:
    """Réglages d'un déploiement. Les défauts sont ceux d'avant toute config."""

    # --- Seuils de calibration, à recalibrer sur données réelles ---
    max_fix_age_ms: int = 15_000        # au-delà, le point ne prouve rien sur l'instant
    max_h_accuracy_m: float = 50.0      # au-delà, la position est trop floue
    min_h_accuracy_m: float = 1.0       # en deçà, précision anormalement parfaite
    max_sign_latency_ms: int = 3_000    # au-delà, une manipulation est probable
    max_clock_skew_ms: int = 300_000    # écart toléré avec l'horloge serveur
    baro_alt_tolerance_m: float = 60.0  # écart toléré GNSS / barométrique

    # --- Politique de distribution ---
    #
    # Sur Android, « binaire reconnu » signifie très précisément *ce binaire
    # est celui que Google Play distribue*. Une application diffusée hors
    # Play ne l'obtient jamais, même saine et même déclarée en Play Console.
    # Laisser F revient donc à refuser toute diffusion hors magasin — un
    # choix, pas une fatalité. iOS n'a pas cette limite : App Attest ignore
    # le canal de distribution. Voir modèle de menace §7, limite 7.
    unrecognized_app_grade: Grade = Grade.F

    # Empreintes SHA-256, telles que le fournisseur les rend, des certificats
    # de signature que ce déploiement reconnaît comme siens.
    #
    # Sans elles, « non reconnu par le magasin » recouvre deux situations que
    # rien ne distingue : un binaire reconditionné, et notre propre build
    # diffusée hors magasin. Le discriminant est solide — reconditionner
    # oblige à resigner, donc change l'empreinte, et le client ne calcule pas
    # cette empreinte lui-même.
    #
    # Un tuple et non un ensemble : l'ordre d'un frozenset varie d'une
    # exécution à l'autre, ce qui rendrait `deviations()` instable et deux
    # verdicts identiques incomparables.
    trusted_app_certificates: tuple[str, ...] = ()

    # Note d'un binaire que le magasin ne reconnaît pas mais dont l'empreinte
    # de certificat figure ci-dessus. Inerte tant que la liste est vide : un
    # déploiement qui ne configure rien retrouve exactement le comportement
    # d'avant.
    #
    # C et non B, et le motif n'est pas cosmétique : dans le profil `capture`,
    # `origin` est déjà plafonné à B par RECAPTURE_CAP. Une dégradation à B y
    # serait donc *invisible au niveau* — le mécanisme n'aurait dégradé que
    # sur le papier. C fait sortir le verdict en DEGRADED dans les deux
    # profils, ce qui est précisément ce qu'on attend d'un binaire dont le
    # magasin ne garantit pas les octets.
    deployment_signed_app_grade: Grade = Grade.C

    def deviations(self) -> list[str]:
        """Réglages qui s'écartent du défaut, pour le résultat de vérification.

        Vide lorsque la politique est celle par défaut : un déploiement qui
        ne configure rien ne pollue pas ses résultats.
        """
        defauts = GradingPolicy()
        return [
            f"{f.name}={getattr(self, f.name)!s}"
            for f in fields(self)
            if getattr(self, f.name) != getattr(defauts, f.name)
        ]


DEFAULT_POLICY = GradingPolicy()

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


def grade_integrity(
    att: AttestationOutcome,
    hardware_backed: bool,
    boot_verified_at_enrollment: bool | None = None,
) -> PropertyResult:
    """Intégrité — la seule propriété qui garde une part **hors ligne**.

    `boot_verified_at_enrollment` vient de `RootOfTrust`, lu dans la liste
    `teeEnforced` de l'attestation de clé. Il se vérifie sans réseau, ce qui
    en fait le seul signal d'intégrité que le serveur possède en propre côté
    Android — le verdict Play Integrity, lui, exige un appel à Google par
    enveloppe (ADR-0006).

    Sa limite est dans son nom : il vaut **à l'enrôlement**. Un attaquant
    s'enrôle chargeur verrouillé, puis déverrouille. Il ne remplace donc pas
    le verdict vivant, il le complète à un autre instant. `None` signifie que
    l'appareil ne publie pas ce bloc — une absence, jamais une garantie.
    """
    r = PropertyResult(Grade.A, evidence=["cose-valid"])
    if hardware_backed:
        r.evidence.append("key-attested-hardware")
    else:
        r.grade = Grade.C
        r.notes.append("clé non adossée au matériel")

    if boot_verified_at_enrollment is True:
        # Le suffixe n'est pas décoratif : sans lui, un lecteur prendrait ce
        # jeton pour un état courant. Il dit un fait daté.
        r.evidence.append("boot-verified-at-enrollment")
    elif boot_verified_at_enrollment is False:
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append(
            "démarrage vérifié absent à l'enrôlement : chargeur d'amorçage "
            "déverrouillé, ou image non signée"
        )
    return r


def grade_origin(
    claims: CaptureClaims,
    att: AttestationOutcome,
    profile: Profile,
    policy: GradingPolicy = DEFAULT_POLICY,
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
    elif (
        att.app_certificate_digest is not None
        and att.app_certificate_digest in policy.trusted_app_certificates
    ):
        # Le magasin ne se porte pas garant, mais la signature oui : ce binaire
        # est bien celui que ce déploiement a produit. On dégrade sans arrêter
        # les contrôles — l'application est authentifiée, pas blanchie.
        r.grade = min(r.grade, policy.deployment_signed_app_grade, key=_grade_rank)
        r.evidence.append("app-deployment-signed")
        r.notes.append(
            "binaire non reconnu par le magasin, mais signé par un certificat "
            "déclaré par ce déploiement"
        )
    else:
        r.grade = policy.unrecognized_app_grade
        r.notes.append(
            "binaire non reconnu par le fournisseur d'attestation — reconditionné, "
            "ou simplement distribué hors du magasin officiel"
        )
        return r

    if att.integrity is DeviceIntegrity.FAILED:
        r.grade = Grade.F
        r.notes.append("intégrité de l'appareil en échec")
        return r

    if claims.media.sign_latency_ms > policy.max_sign_latency_ms:
        # `min` et non une affectation : une note déjà plus basse ne doit pas
        # remonter. Sans garde, un binaire signé par le déploiement et noté
        # sous C par la politique se verrait *promu* par une latence anormale.
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append(
            f"latence payload→signature anormale : {claims.media.sign_latency_ms} ms"
        )

    if profile is Profile.CAPTURE:
        r.grade = min(r.grade, RECAPTURE_CAP, key=_grade_rank)
        r.notes.append(RECAPTURE_CAP_REASON)
    return r


def grade_position(
    claims: CaptureClaims,
    att: AttestationOutcome,
    policy: GradingPolicy = DEFAULT_POLICY,
) -> PropertyResult:
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

    if p.fix_age_ms > policy.max_fix_age_ms:
        r.grade = Grade.C
        r.notes.append(f"point de position vieux de {p.fix_age_ms} ms au déclenchement")

    if p.h_accuracy > policy.max_h_accuracy_m:
        r.grade = min(r.grade, Grade.C, key=_grade_rank)
        r.notes.append(f"précision horizontale insuffisante : {p.h_accuracy} m")
    elif p.h_accuracy < policy.min_h_accuracy_m:
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
            if delta <= policy.baro_alt_tolerance_m:
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
    policy: GradingPolicy = DEFAULT_POLICY,
) -> PropertyResult:
    r = PropertyResult(Grade.B, evidence=["nonce-fresh"])

    skew = abs(claims.timing.wall_ms - server_now_ms)
    if skew <= policy.max_clock_skew_ms:
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
