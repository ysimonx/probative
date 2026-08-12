"""Pipeline de vérification.

L'ordre des étapes suit la spécification §5, et cet ordre est
significatif : on écarte au plus vite et au moins cher. Les étapes 1 à 4
sont locales et coûtent une milliseconde ; l'appel au fournisseur
d'attestation vient après, jamais avant. Un vérificateur qui interroge
Google ou Apple avant d'avoir vérifié la signature offre gratuitement un
amplificateur de déni de service.
"""

from __future__ import annotations

import hashlib
import time

from . import cose, grading, profiles
from .attestation import AttestationVerifier, DeviceIntegrity
from .errors import (
    AssertionCounterRegression,
    BindingMismatch,
    ChainBroken,
    MediaDigestMismatch,
    ProfileMismatch,
    UnsupportedSpecVersion,
    VerificationError,
)
from .model import (
    SPEC_SUPPORTED,
    CaptureClaims,
    Freshness,
    Platform,
    Property,
    PropertyResult,
    VerificationResult,
)
from .store import DeviceStore, NonceStore


class Verifier:
    def __init__(
        self,
        *,
        nonce_store: NonceStore,
        device_store: DeviceStore,
        attestation: AttestationVerifier,
        strict_chain: bool = False,
        policy: grading.GradingPolicy = grading.DEFAULT_POLICY,
    ) -> None:
        self._nonces = nonce_store
        self._devices = device_store
        self._attestation = attestation
        self._strict_chain = strict_chain
        # Réglages du déploiement. Les écarts au défaut voyagent dans le
        # résultat : un verdict calculé sous d'autres règles n'est pas
        # comparable à un verdict calculé sous celles d'origine.
        self._policy = policy

    def verify(
        self,
        envelope: bytes,
        *,
        media_bytes: bytes | None = None,
        now_ms: int | None = None,
    ) -> VerificationResult:
        """Vérifie une enveloppe.

        `media_bytes` est optionnel : l'empreinte n'est recalculée que si
        le payload est fourni. Cela permet de rejeter une enveloppe avant
        d'avoir dépensé la bande passante du transfert.
        """
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        try:
            return self._verify(envelope, media_bytes, now_ms)
        except VerificationError as exc:
            return VerificationResult.rejected(exc.code, exc.detail)

    # -- interne ---------------------------------------------------------

    def _verify(
        self, envelope: bytes, media_bytes: bytes | None, now_ms: int
    ) -> VerificationResult:
        # 1. version de spécification et profil connus
        sign1 = cose.decode(envelope)
        spec = sign1.spec
        if spec not in SPEC_SUPPORTED:
            raise UnsupportedSpecVersion(f"version {spec!r} non supportée")

        profile = profiles.parse(sign1.profile)
        claims = CaptureClaims.decode(sign1.payload())
        profiles.require_fields(profile, claims)

        # 2. nonce connu, non consommé, non expiré, émis pour cet appareil
        #    et pour ce profil
        nonce_rec = self._nonces.consume(claims.nonce, now_ms, kid=sign1.kid)
        if nonce_rec.profile is not profile:
            # Le profil est signé, donc non modifiable en vol — mais un
            # client compromis reste libre de *déclarer* le noyau pour une
            # acquisition, et d'échapper ainsi au plafond de recapture.
            # C'est le nonce qui ferme cette porte : le serveur a demandé
            # une acquisition, il doit en recevoir une.
            raise ProfileMismatch(
                f"nonce émis pour le profil {nonce_rec.profile.value!r}, "
                f"enveloppe déclarée {profile.value!r}"
            )

        # 3. signature sous la clé enrôlée
        device = self._devices.get(sign1.kid)
        cose.verify_signature(sign1, device.public_key)

        # 4. règle R1 — liaison de la fraîcheur au contenu
        freshness_raw = sign1.unprotected.get(cose.HDR_FRESHNESS)
        if freshness_raw is None:
            raise BindingMismatch("aucune preuve de fraîcheur dans l'enveloppe")
        freshness = Freshness.decode(freshness_raw)
        expected = cose.binding_challenge(sign1.payload_bytes, claims.nonce)

        # 5. validation auprès du fournisseur
        att = self._attestation.verify(
            platform=claims.posture.platform.value,
            token=freshness.token,
            expected_challenge=expected,
            key_id=sign1.kid,
            attestation_key=device.attestation_key,
        )

        flags: list[str] = []
        if att.integrity is DeviceIntegrity.UNAVAILABLE:
            flags.append("ATTESTATION_UNAVAILABLE")

        # 6. compteur d'assertion strictement croissant (iOS)
        #
        # Le compteur de l'en-tête de fraîcheur n'est couvert par aucune
        # signature : il est déclaratif. Celui que le fournisseur extrait
        # de l'assertion, lui, est signé. Quand les deux existent, seul le
        # second fait foi, et un désaccord est un rejet — un client qui
        # annonce un compteur autre que celui qu'il a réellement obtenu
        # cherche à influencer l'ordonnancement.
        counter = att.counter if att.counter is not None else freshness.counter
        if (
            att.counter is not None
            and freshness.counter is not None
            and freshness.counter != att.counter
        ):
            raise AssertionCounterRegression(
                f"compteur déclaré {freshness.counter}, compteur signé {att.counter}"
            )

        counter_verified = False
        if claims.posture.platform is Platform.IOS and counter is not None:
            if counter <= device.assertion_counter:
                raise AssertionCounterRegression(
                    f"compteur reçu {counter}, dernier connu {device.assertion_counter}"
                )
            device.assertion_counter = counter
            counter_verified = True

        # 7. chaînage d'enveloppes (Android)
        chain_verified = False
        if claims.prev_digest is not None:
            if device.last_envelope_digest is None:
                flags.append("CHAIN_FIRST_LINK_UNKNOWN")
            elif claims.prev_digest != device.last_envelope_digest:
                if self._strict_chain:
                    raise ChainBroken("l'enveloppe précédente référencée est inconnue")
                flags.append("CHAIN_BROKEN")
            else:
                chain_verified = True
        elif claims.posture.platform is Platform.ANDROID:
            flags.append("CHAIN_ABSENT")

        device.last_envelope_digest = hashlib.sha256(envelope).digest()
        self._devices.update(device)

        # 8. empreinte du payload
        if media_bytes is not None:
            if hashlib.sha256(media_bytes).digest() != claims.media.digest:
                raise MediaDigestMismatch(
                    "les octets reçus ne correspondent pas à l'empreinte signée"
                )
        else:
            flags.append("MEDIA_NOT_PROVIDED")

        # 9. grades des propriétés du profil déclaré
        graded_by_profile = profiles.properties_for(profile)
        properties: dict[Property, PropertyResult] = {
            Property.INTEGRITY: grading.grade_integrity(att, device.hardware_backed),
            Property.ORIGIN: grading.grade_origin(claims, att, profile, self._policy),
            Property.TIME: grading.grade_time(
                claims,
                att,
                server_now_ms=now_ms,
                offline=nonce_rec.offline,
                counter_verified=counter_verified,
                chain_verified=chain_verified,
                policy=self._policy,
            ),
        }
        if Property.POSITION in graded_by_profile:
            properties[Property.POSITION] = grading.grade_position(claims, att, self._policy)

        if set(properties) != set(graded_by_profile):
            # Faute de câblage, pas entrée hostile : un profil qui annonce
            # une propriété non notée ici rendrait un verdict amputé sans
            # le dire. On échoue bruyamment plutôt que de rejeter, pour que
            # ce soit un bogue visible et non un refus mystérieux.
            raise NotImplementedError(
                f"profil {profile.value!r} : propriétés annoncées "
                f"{sorted(p.value for p in graded_by_profile)}, notées "
                f"{sorted(p.value for p in properties)}"
            )

        for p in properties.values():
            p.evidence.extend(att.evidence)
            # Les notes du fournisseur portent le motif *précis* — liaison
            # R1 non établie, application inattendue, substitut actif. Sans
            # cette ligne elles étaient perdues, et `level_reason` ne
            # gardait que le motif générique de `grade_origin`. Un rejet
            # sans motif exploitable est ingérable en support.
            p.notes.extend(att.notes)

        # Réclamations non reconnues : signalées, jamais pénalisantes.
        known = {"baro", "baro-alt", "motion", "steps", "activity"}
        if any(c.type not in known for c in claims.claims):
            flags.append("UNKNOWN_CLAIMS")

        # Champs présents que le profil déclaré ne note pas. Ils sont
        # signés, donc d'apparence fiable, et n'ont subi aucun contrôle.
        ungraded = profiles.ungraded_fields(profile, claims)
        if ungraded:
            flags.append("UNGRADED_FIELDS")

        level, reason = grading.overall_level(properties, offline=nonce_rec.offline)

        # 10. le nonce est déjà marqué consommé par le store, à l'étape 2.
        return VerificationResult(
            spec=spec,
            profile=profile.value,
            policy=self._policy.deviations(),
            level=level,
            properties=properties,
            flags=flags,
            level_reason=reason,
        )
