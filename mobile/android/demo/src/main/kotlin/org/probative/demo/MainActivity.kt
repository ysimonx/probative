package org.probative.demo

import android.app.Activity
import android.os.Bundle
import android.util.TypedValue
import android.widget.TextView
import org.probative.core.Spec

/**
 * Ecran unique de la demonstration.
 *
 * A l'etape A1 il ne fait qu'une chose : prouver que l'AAR se consomme depuis une
 * application ordinaire, sans AndroidX ni greffon de framework. La capture arrive en A4.
 *
 * Pas de fichier de ressources : la demonstration doit rester assez pauvre pour qu'on
 * ne soit jamais tente d'y loger de la logique qui appartient au coeur.
 */
public class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val report = buildString {
            appendLine("probative — coeur natif Android")
            appendLine()
            appendLine("specification  ${Spec.VERSION}")
            appendLine("type MIME      ${Spec.MIME_TYPE}")
            appendLine("extension      .${Spec.FILE_EXTENSION}")
            appendLine("algorithme     ES256 (${Spec.ALG_ES256})")
            appendLine()
            appendLine("Etape A1 : squelette. Aucune capture, aucune cle.")
        }

        setContentView(
            TextView(this).apply {
                text = report
                setTextIsSelectable(true)
                setPadding(48, 96, 48, 48)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            },
        )
    }
}
