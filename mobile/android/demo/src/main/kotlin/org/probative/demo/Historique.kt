package org.probative.demo

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Une campagne et ce qu'elle a produit — conservée pour être relue.
 *
 * L'historique existe parce qu'une campagne isolée ne dit rien de la
 * dispersion. Trois relevés de `media[6]` ont déjà montré du simple au double
 * sur la même tablette ; la calibration des seuils de `grading.py` (étape A7)
 * demandera *n* prises par appareil, et il faut pouvoir les comparer sans
 * recoller des extraits de logcat.
 *
 * **Les octets sont conservés, pas seulement leurs empreintes.** L'enveloppe ne
 * porte qu'un condensat du média : sans les octets, le verdict sur le contenu
 * ne vaut plus rien, et aucune recompression ne les rattrape (ADR-0007
 * point 5). Une démonstration qui afficherait une vignette ré-encodée
 * trahirait exactement ce qu'elle prétend montrer — on garde donc le tampon
 * d'origine et on ne le décode que pour l'affichage.
 *
 * Mémoire seule : rien n'est persisté d'un lancement à l'autre. C'est un banc
 * de mesure, pas un stockage de preuves, et le laisser croire serait pire que
 * de ne rien garder.
 */
internal class Prise(
    val index: Int,
    /** Numéro de visite. Une visite close, la suivante repart d'une tête attestée. */
    val visite: Int,
    val instantMs: Long,
    val profil: String,
    val niveau: String,
    val motif: String,
    val proprietes: List<String>,
    val drapeaux: String,
    /** `media[6]` tel que scellé — le seul chiffre confronté au seuil. */
    val mediaSixMs: Long,
    /** Octets du média, intacts. `null` pour une enveloppe sans acquisition. */
    val photo: ByteArray?,
    val largeur: Int,
    val hauteur: Int,
    val typeMime: String,
    val enveloppe: ByteArray,
    val defiR1: String,
    val kid: String,
    /** Décomposition de l'acquisition, absente hors profil `capture`. */
    val decomposition: String?,
) {
    val heure: String
        get() = SimpleDateFormat("HH:mm:ss", Locale.FRANCE).format(Date(instantMs))

    /** Une ligne de tableau : ce qui distingue une prise d'une autre au premier coup d'œil. */
    fun ligne(): String = buildString {
        append("%02d  v%d  %s  %-8s %-9s".format(index, visite, heure, profil, niveau))
        append("media[6] %4d ms".format(mediaSixMs))
        if (photo != null) append("  %d×%d  %d ko".format(largeur, hauteur, photo.size / 1024))
    }
}

/**
 * Le tableau des prises, dans l'ordre où elles ont été faites.
 *
 * Objet et non champ d'activité : la rotation recrée l'activité, et un
 * historique qui disparaîtrait à chaque quart de tour ne servirait à rien —
 * la leçon du 2026-08-17, où la rotation relançait la campagne et fermait la
 * session de capture.
 */
internal object Historique {

    private val prises = mutableListOf<Prise>()

    @Synchronized
    fun ajouter(
        visite: Int,
        profil: String,
        niveau: String,
        motif: String,
        proprietes: List<String>,
        drapeaux: String,
        mediaSixMs: Long,
        photo: ByteArray?,
        largeur: Int,
        hauteur: Int,
        typeMime: String,
        enveloppe: ByteArray,
        defiR1: String,
        kid: String,
        decomposition: String?,
    ): Prise {
        val prise = Prise(
            index = prises.size + 1,
            visite = visite,
            instantMs = System.currentTimeMillis(),
            profil = profil,
            niveau = niveau,
            motif = motif,
            proprietes = proprietes,
            drapeaux = drapeaux,
            mediaSixMs = mediaSixMs,
            photo = photo,
            largeur = largeur,
            hauteur = hauteur,
            typeMime = typeMime,
            enveloppe = enveloppe,
            defiR1 = defiR1,
            kid = kid,
            decomposition = decomposition,
        )
        prises.add(prise)
        return prise
    }

    @Synchronized
    fun toutes(): List<Prise> = prises.toList()

    @Synchronized
    fun compte(): Int = prises.size

    /**
     * Dispersion de `media[6]` sur les prises d'un profil — la grandeur qui
     * intéresse la calibration, et que trois relevés ne suffisent pas à fixer.
     */
    @Synchronized
    fun dispersion(profil: String): String {
        val valeurs = prises.filter { it.profil == profil }.map { it.mediaSixMs }
        if (valeurs.isEmpty()) return "aucune prise en $profil"
        return "media[6] en %s : %d prises, min %d, max %d, median %d ms".format(
            profil,
            valeurs.size,
            valeurs.min(),
            valeurs.max(),
            valeurs.sorted()[valeurs.size / 2],
        )
    }
}
