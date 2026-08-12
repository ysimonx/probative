"""Profils d'enveloppe — voir ADR-0005.

Le noyau est la couche partagée par tout payload : clé attestée, règles
R1/R2/R3, empreinte du payload, temps, posture, fraîcheur. Un profil s'y
ajoute et ne fait que trois choses : exiger des champs supplémentaires,
étendre l'ensemble des propriétés notées, et éventuellement plafonner
l'une d'elles.

Ce module est délibérément une table, pas un mécanisme d'extension. Un
profil se justifie quand une propriété apparaît, disparaît, ou change de
règle de notation — jamais quand seul le payload change de forme. Sans ce
critère, le vérificateur deviendrait un registre de types MIME.
"""

from __future__ import annotations

from .errors import MalformedEnvelope, UnknownProfile
from .model import CaptureClaims, Profile, Property

# Les propriétés que tout profil note, parce qu'elles ne parlent que des
# octets et de l'appareil : ni l'une ni l'autre ne suppose un capteur.
CORE_PROPERTIES = (Property.INTEGRITY, Property.ORIGIN, Property.TIME)

_PROPERTIES: dict[Profile, tuple[Property, ...]] = {
    Profile.CORE: CORE_PROPERTIES,
    Profile.CAPTURE: (*CORE_PROPERTIES, Property.POSITION),
}


def parse(raw: str) -> Profile:
    """Convertit le label 102 en profil, ou refuse de juger.

    Un vérificateur qui ne connaît pas un profil doit s'arrêter là. Juger
    quand même avec les règles du noyau donnerait un verdict qui a l'air
    complet en ayant silencieusement omis les propriétés du profil — et,
    pour `capture`, son plafond de recapture analogique.
    """
    try:
        return Profile(raw)
    except ValueError as exc:
        raise UnknownProfile(f"profil {raw!r} inconnu de ce vérificateur") from exc


def properties_for(profile: Profile) -> tuple[Property, ...]:
    return _PROPERTIES[profile]


def ungraded_fields(profile: Profile, claims: CaptureClaims) -> list[str]:
    """Champs présents dans la charge utile que ce profil ne note pas.

    Le cas qui compte : une enveloppe `core` portant une position. Elle
    est signée, donc d'apparence fiable, et n'a subi **aucun** contrôle —
    ni indicateur de position simulée, ni précision, ni corroboration
    barométrique. Le résultat omet la propriété `position`, ce qu'un
    lecteur attentif remarque ; un lecteur pressé lira une latitude signée
    et la croira jugée.

    On signale plutôt qu'on rejette : ces champs ne sont pas malformés, et
    la tolérance aux champs inconnus est ce qui rend les versions mineures
    non cassantes (spec §8). Mais on ne les laisse pas passer en silence —
    une donnée qui traverse le calcul des grades sans être remarquée est
    précisément ce que ce dépôt refuse.
    """
    if profile is Profile.CAPTURE:
        return []
    presents = []
    if claims.position is not None:
        presents.append("position")
    if claims.claims:
        presents.append("corroboration")
    return presents


def require_fields(profile: Profile, claims: CaptureClaims) -> None:
    """Vérifie que la charge utile porte ce que le profil exige.

    Le décodage établit la forme, le profil établit ce qu'il faut y
    trouver. Séparer les deux est ce qui permet à `position` d'être
    optionnelle dans le schéma sans être facultative dans les faits.
    """
    if profile is Profile.CAPTURE:
        if claims.position is None:
            raise MalformedEnvelope("profil capture : position obligatoire")
        # Une acquisition sans dimensions ni durée ne décrit rien
        # d'exploitable — un son a une durée, une image des dimensions,
        # une vidéo les deux. Exiger l'un *ou* l'autre, et non les
        # dimensions seules, est ce qui fait tenir l'audio dans ce profil.
        sans_dimensions = claims.media.width is None or claims.media.height is None
        if sans_dimensions and claims.media.duration_ms is None:
            raise MalformedEnvelope("profil capture : dimensions ou durée obligatoires")
