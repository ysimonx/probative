# attested-capture (vérificateur Python)

Vérificateur serveur d'enveloppes de capture photo géolocalisée attestée,
spécification `ac/0.1`.

Le client collecte et signe des preuves, le serveur juge. Le code client est
intégralement considéré comme hostile : aucune décision de validité n'est prise
sur l'appareil, et l'API n'expose jamais de booléen de confiance.

Le dépôt complet — modèle de menace, spécification d'enveloppe, clients mobiles —
se trouve un niveau au-dessus.

## Licence

Apache-2.0.
