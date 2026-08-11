package org.probative.core

/**
 * Constantes normatives de la specification `probative/0.1`.
 *
 * Ces valeurs entrent dans l'en-tete protege du `COSE_Sign1`, donc dans les octets
 * couverts par la signature. Une divergence avec le verificateur serveur casse la
 * verification au lieu de degrader silencieusement le resultat -- c'est la propriete
 * recherchee : une incoherence de version doit etre bruyante.
 *
 * Reference : `docs/envelope-spec.md`, sections 7 et 8.
 */
public object Spec {

    /** Valeur du label [Header.SPEC_VERSION] de l'en-tete protege. */
    public const val VERSION: String = "probative/0.1"

    /** Type MIME de l'enveloppe serialisee. */
    public const val MIME_TYPE: String = "application/vnd.probative+cose"

    /** Extension de fichier, sans le point. */
    public const val FILE_EXTENSION: String = "prbv"

    /**
     * ES256, seul algorithme de signature admis en v0.1.
     *
     * Restreindre le choix a un unique algorithme retire au producteur d'enveloppe
     * toute latitude de negociation -- surface d'attaque en moins.
     */
    public const val ALG_ES256: Long = -7

    /** Labels de l'en-tete protege : 1 et 4 viennent de la RFC 9052, 100 et 101 sont propres a la specification. */
    public object Header {
        public const val ALG: Long = 1
        public const val KID: Long = 4
        public const val SPEC_VERSION: Long = 100
        public const val DEPLOYMENT: Long = 101
    }
}
