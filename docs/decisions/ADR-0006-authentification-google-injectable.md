# ADR-0006 — Authentification Google par couture, defaut sans dependance

**Statut :** accepte
**Date :** 2026-08

## Contexte

La phase B doit appeler `decodeIntegrityToken` pour lire le verdict d'un jeton Play
Integrity. Le dechiffrement local n'est pas ouvert a ce projet : les cles se
telechargent depuis la Play Console et exigent que l'application soit disponible sur
Google Play, ce que la distribution hors magasin -- que ce depot sert delibrement --
ne permet pas. L'appel a Google est donc le seul chemin.

Cet appel demande une authentification OAuth 2.0 en compte de service : un JWT signe
(flux JWT-bearer, RFC 7523) echange contre un jeton d'acces d'une heure.

Le verificateur ne depend aujourd'hui que de **deux** paquets, `cbor2` et
`cryptography`. La bibliotheque officielle `google-auth` en ajoute **huit** :
elle-meme, `pyasn1`, `pyasn1_modules`, `requests`, `certifi`,
`charset-normalizer`, `idna`, `urllib3`.

Deux faits interdisent de cabler l'un ou l'autre en dur :

1. Un deploiement sur Google Cloud n'utilise **pas** de fichier de cle. Il passe par
   la federation d'identite de charge de travail, que seule `google-auth` gere -- et
   que la console de Google recommande explicitement au detriment des cles
   telechargees.
2. Un deploiement **iOS seul** n'appellera jamais Play Integrity. Lui imposer huit
   paquets serait gratuit.

## Decision

Le verificateur expose une **couture** : un `Protocol` `AccessTokenProvider`, dont la
seule methode rend un jeton d'acces portant la portee `playintegrity`.

Le depot livre une implementation par defaut, `ServiceAccountKeyProvider`, qui
construit et signe son JWT elle-meme -- `cryptography` sait deja signer en RSA-SHA256,
`urllib` est dans la bibliotheque standard. **Aucune dependance nouvelle.**

Un deploiement qui veut `google-auth`, la federation d'identite, ou tout autre
mecanisme, injecte son propre fournisseur. Le depot n'en depend jamais.

## Justification

**Le sens de la cryptographie compte.** « On n'ecrit pas sa crypto soi-meme » vise la
*verification d'une entree hostile*, ou un defaut laisse entrer un attaquant
silencieusement. Ici il s'agit de *signer une assertion que nous emettons* : un defaut
fait rejeter l'appel par Google au premier essai, bruyamment, dans tous les
environnements. Ni surface d'attaque, ni mode de defaillance silencieux.

**Le precedent est etabli.** Ce depot ecrit deja a la main son encodeur CBOR, sa
couche COSE, son lecteur DER, et la validation de chaine X.509 d'App Attest -- laquelle
releve, elle, de la verification d'entree hostile, donc bien plus risquee. Refuser
45 lignes de JWT apres cela serait incoherent. L'extra `[devserver]` avait deja ete
abandonne pour le meme motif (ADR-0001, surface minimale).

**La reversibilite est asymetrique.** Une dependance s'ajoute facilement et se retire
tres difficilement une fois que des utilisateurs en dependent. La couture se pose
maintenant pour presque rien, et n'interdit aucune des deux options par la suite.

**Le motif existe deja.** `AttestationVerifier` est une classe abstraite precisement
pour isoler la dependance reseau. On prolonge ce choix au lieu d'en inventer un autre.

## Consequences

- Les dependances du verificateur restent a **deux**. Un deploiement iOS seul ne paie
  rien pour Android.
- Un deploiement Google Cloud injecte `google-auth` en trois lignes, et recupere la
  federation d'identite que le defaut ne fournira jamais. **C'est voulu** : le defaut
  couvre le fichier de cle, pas l'infrastructure Google.
- Le depot maintient environ 45 lignes de flux JWT-bearer, cache de jeton compris.
  La marge de renouvellement d'une minute existe parce qu'une horloge serveur en
  avance ferait rejeter un jeton juge encore valide localement.
- `CredentialsError` remonte le corps de la reponse de Google et non le seul code
  HTTP : `invalid_grant` sur une horloge decalee est indiagnosticable autrement.

## Verification

Eprouve contre l'API reelle le 2026-08-12, dans le venv du projet -- ni `google-auth`
ni `requests` installes. Jeton Play Integrity reel capture sur SM-X200, dechiffre en
HTTP 200, `requestHash` confronte au R1 recalcule cote hote : identique. Le cache
ressert le jeton d'acces sans second aller-retour.

## Ce qui reviendrait sur cette decision

Si Google faisait evoluer son flux d'authentification au point que 45 lignes ne
suffisent plus -- rotation obligatoire, attestation du client, mTLS -- le defaut
maison deviendrait un fardeau. La couture, elle, resterait : il suffirait alors de
changer l'implementation par defaut pour `google-auth`, sans toucher aux
deploiements qui injectent deja le leur. C'est precisement ce que la couture achete.
