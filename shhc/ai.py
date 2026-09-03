"""Recommandations redigees par un modele de langage.

Les regles de `rules` disent CE QUI ne va pas ; ce module dit POURQUOI c'est
un probleme sur ce site precis et QUOI ecrire pour le corriger, en tenant
compte de la valeur reellement observee.

Deux garde-fous structurent tout le module :

1. **Il est optionnel.** Sans cle API, `advise()` leve `AIUnavailable` et
   l'appelant retombe sur les recommandations statiques des `Finding`. Le
   produit reste utilisable hors ligne, en CI, et dans les tests.
2. **La sortie du modele n'est jamais crue sur parole.** Un LLM peut inventer
   un en-tete, renvoyer du texte hors JSON, ou depasser toute longueur
   raisonnable. `_parse_reponse()` filtre, tronque et normalise avant que
   quoi que ce soit ne remonte vers l'affichage.

La configuration se lit dans l'environnement, ou a defaut dans un fichier
`.env` a la racine du depot - voir `_charger_env`.

L'endpoint vise est celui de Groq (gratuit), mais le dialecte utilise est
celui, tres repandu, de `POST /chat/completions`. Changer de fournisseur ne
demande donc que deux variables :

    SHHC_AI_KEY       la cle API (a defaut : GROQ_API_KEY)
    SHHC_AI_BASE_URL  https://api.groq.com/openai/v1        (defaut)
    SHHC_AI_MODEL     openai/gpt-oss-120b                   (defaut)

Exemples testes :
    Gemini     base_url=https://generativelanguage.googleapis.com/v1beta/openai
               model=gemini-2.5-flash
    OpenRouter base_url=https://openrouter.ai/api/v1
               model=meta-llama/llama-3.3-70b-instruct:free
    Ollama     base_url=http://localhost:11434/v1  model=llama3.1  (cle bidon)
"""

import json
import os
from pathlib import Path

import httpx

from shhc.models import Advice, AiReport, Finding

#: Fichier de configuration locale, a la racine du depot. Il est dans le
#: .gitignore : c'est l'endroit prevu pour une cle, pas le depot.
FICHIER_ENV = Path(__file__).resolve().parent.parent / ".env"

#: Valeurs par defaut : Groq, dont le palier gratuit ne demande pas de carte.
#:
#: Le catalogue d'un fournisseur bouge : un modele retire fait repondre 404 a
#: `/chat/completions`. La liste a jour est toujours lisible par un simple
#: `GET {base_url}/models` - c'est le premier reflexe en cas de 404.
DEFAUT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAUT_MODEL = "openai/gpt-oss-120b"

#: Le modele redige quelques paragraphes, pas un roman.
MAX_TOKENS = 1200

#: Temperature basse : on veut un conseil reproductible, pas de la creativite.
TEMPERATURE = 0.2

#: Plus genereux que le fetch (10 s) : un LLM met quelques secondes a repondre.
TIMEOUT = 25.0

#: Bornes de securite sur ce que le modele renvoie, appliquees a l'affichage.
MAX_SUMMARY = 600
MAX_TEXTE = 400
MAX_EXEMPLE = 300

#: Une valeur d'en-tete peut peser plusieurs kilo-octets (grosse CSP). On la
#: tronque avant de l'envoyer : au-dela, elle ne change plus le diagnostic.
MAX_VALEUR_ENVOYEE = 800

PRIORITES = ("haute", "moyenne", "basse")

SYSTEM_PROMPT = """\
Tu es un expert en securite web. Tu recois le resultat d'un audit des en-tetes \
de securite HTTP d'un site : pour chaque en-tete, son statut (ok, weak, missing) \
et sa valeur exacte telle qu'elle a ete observee.

Redige des recommandations en francais, concretes et adaptees a CE site.

Regles :
- Appuie-toi sur la valeur reellement observee, cite-la quand c'est utile.
- Une recommandation par en-tete non conforme, aucune pour les en-tetes "ok".
- `risque` : la consequence concrete et exploitable, une phrase, sans jargon inutile.
- `action` : quoi faire, a l'imperatif, en une ou deux phrases.
- `exemple` : la ligne d'en-tete complete a poser, prete a copier. Pour une CSP, \
propose une politique realiste deduite de ce que le site semble faire, pas un \
`default-src 'none'` qui casserait la page.
- `priorite` : "haute", "moyenne" ou "basse", selon l'exploitabilite reelle.
- N'invente jamais d'en-tete absent de l'audit.

Reponds UNIQUEMENT avec un objet JSON de cette forme, sans texte autour :
{"synthese": "2 a 3 phrases sur la posture globale du site",
 "recommandations": [{"header": "...", "risque": "...", "action": "...",
                      "exemple": "...", "priorite": "haute"}]}"""


class AIUnavailable(Exception):
    """L'IA n'a pas pu repondre. Message deja lisible par un humain.

    Volontairement large : cle absente, reseau coupe, quota depasse, JSON
    illisible. L'appelant n'a qu'une decision a prendre - retomber sur les
    recommandations statiques - donc un seul type d'erreur suffit.
    """


#: Le fichier .env n'est lu qu'une fois par processus.
_env_charge = False


def _charger_env() -> None:
    """Verse le contenu de `.env` dans l'environnement, une seule fois.

    Une quinzaine de lignes plutot qu'une dependance : `python-dotenv` ne
    ferait rien de plus ici, et le fichier a lire tient en trois variables.

    L'environnement reel a TOUJOURS la priorite. C'est la regle habituelle, et
    surtout la seule sensee en production : sur Render, la variable definie
    dans le tableau de bord ne doit pas pouvoir etre ecrasee par un fichier
    qui trainerait dans l'image.

    Les lignes vides, les commentaires et les lignes sans `=` sont ignores ;
    le prefixe `export` et les guillemets entourants sont acceptes, parce que
    c'est ainsi qu'on colle une variable depuis un shell.
    """
    global _env_charge
    if _env_charge:
        return
    _env_charge = True  # pose avant la lecture : un fichier illisible ne se rejoue pas

    try:
        lignes = FICHIER_ENV.read_text(encoding="utf-8").splitlines()
    except OSError:
        return  # absent ou illisible : ce n'est pas une erreur, la cle est optionnelle

    for ligne in lignes:
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#") or "=" not in ligne:
            continue
        nom, _, valeur = ligne.removeprefix("export ").partition("=")
        nom, valeur = nom.strip(), valeur.strip()
        if len(valeur) >= 2 and valeur[0] == valeur[-1] and valeur[0] in "\"'":
            valeur = valeur[1:-1]
        if nom and valeur and nom not in os.environ:
            os.environ[nom] = valeur


def _var(nom: str, defaut: str | None = None) -> str | None:
    """Lit une variable, en s'assurant que `.env` a ete pris en compte."""
    _charger_env()
    return os.environ.get(nom, defaut)


def cle_api() -> str | None:
    """La cle API, ou None si aucune n'est configuree.

    `GROQ_API_KEY` est accepte en second choix : c'est le nom que la console
    Groq propose au copier-coller, autant eviter de le renommer a la main.
    """
    return _var("SHHC_AI_KEY") or _var("GROQ_API_KEY") or None


def modele() -> str:
    """Identifiant du modele a interroger."""
    return _var("SHHC_AI_MODEL", DEFAUT_MODEL)


def base_url() -> str:
    """Racine de l'API, sans slash final."""
    return _var("SHHC_AI_BASE_URL", DEFAUT_BASE_URL).rstrip("/")


def is_configured() -> bool:
    """Vrai si une cle est disponible : permet de proposer l'IA sans l'imposer."""
    return cle_api() is not None


def _tronquer(texte: object, limite: int) -> str:
    """Ramene n'importe quelle valeur du modele a une chaine bornee."""
    if not isinstance(texte, str):
        return ""
    texte = " ".join(texte.split())
    if len(texte) <= limite:
        return texte
    return texte[: limite - 3] + "..."


def _payload_findings(findings: list[Finding]) -> list[dict]:
    """Reduit les findings a ce dont le modele a besoin.

    Les points et les poids sont volontairement omis : ils relevent de notre
    bareme, pas de l'analyse de securite, et n'aideraient pas la redaction.
    """
    return [
        {
            "header": f.header,
            "statut": f.status,
            "valeur": _tronquer(f.value, MAX_VALEUR_ENVOYEE) if f.value else None,
            "constat": f.reason,
        }
        for f in findings
    ]


def _parse_reponse(brut: str, findings: list[Finding]) -> tuple[str, list[Advice]]:
    """Valide et normalise le JSON du modele.

    Le contrat impose au modele n'est pas garanti par le protocole : on verifie
    donc tout. Les recommandations qui visent un en-tete absent de l'audit, ou
    deja conforme, sont ecartees - c'est la que se loge le risque d'hallucination.

    L'ordre de sortie est celui des regles, pas celui du modele : la liste doit
    rester du plus critique au moins critique, quoi qu'il renvoie.
    """
    try:
        data = json.loads(brut)
    except json.JSONDecodeError as exc:
        raise AIUnavailable(f"Reponse illisible du modele : {exc}") from exc

    if not isinstance(data, dict):
        raise AIUnavailable("Reponse du modele inattendue : objet JSON attendu.")

    # Index insensible a la casse : le modele reecrit souvent "x-frame-options".
    attendus = {f.header.lower(): f for f in findings if f.status != "ok"}

    par_header: dict[str, Advice] = {}
    for item in data.get("recommandations") or []:
        if not isinstance(item, dict):
            continue
        finding = attendus.get(_tronquer(item.get("header"), 80).lower())
        if finding is None or finding.header in par_header:
            continue  # en-tete invente, deja conforme, ou double

        priorite = _tronquer(item.get("priorite"), 20).lower()
        exemple = _tronquer(item.get("exemple"), MAX_EXEMPLE)
        action = _tronquer(item.get("action"), MAX_TEXTE)
        par_header[finding.header] = Advice(
            header=finding.header,
            risk=_tronquer(item.get("risque"), MAX_TEXTE),
            # Si le modele n'a rien redige d'exploitable, la phrase statique
            # reprend la main : mieux vaut laconique que vide.
            action=action or (finding.recommendation or ""),
            example=exemple or None,
            priority=priorite if priorite in PRIORITES else "moyenne",
        )

    conseils = [par_header[f.header] for f in findings if f.header in par_header]
    return _tronquer(data.get("synthese"), MAX_SUMMARY), conseils


def advise(url: str, findings: list[Finding]) -> AiReport:
    """Fait rediger les recommandations par le modele.

    Args:
        url: l'URL finale analysee, donnee au modele comme contexte.
        findings: le resultat complet de `rules.analyze`, en-tetes conformes
            compris - le modele redige mieux en voyant la configuration entiere.

    Returns:
        Un AiReport. Sa liste `advice` peut etre vide si tous les en-tetes sont
        conformes : il n'y a alors rien a recommander.

    Raises:
        AIUnavailable: cle absente, appel echoue, ou reponse inexploitable.
            L'appelant doit retomber sur `Finding.recommendation`.
    """
    cle = cle_api()
    if cle is None:
        raise AIUnavailable(
            f"Aucune cle API. Definis SHHC_AI_KEY dans l'environnement ou dans "
            f"{FICHIER_ENV.name} (cle gratuite sur console.groq.com)."
        )

    if all(f.status == "ok" for f in findings):
        # Rien a corriger : inutile de payer un aller-retour reseau pour ca.
        return AiReport(summary="", advice=[], model=modele())

    nom_modele = modele()
    corps = {
        "model": nom_modele,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        # Demande au fournisseur de contraindre la sortie a du JSON. Les
        # fournisseurs qui ignorent ce champ restent geres : _parse_reponse
        # leve AIUnavailable si le texte n'est pas du JSON.
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {"url": url, "en_tetes": _payload_findings(findings)},
                    ensure_ascii=False,
                    indent=2,
                ),
            },
        ],
    }

    try:
        reponse = httpx.post(
            f"{base_url()}/chat/completions",
            json=corps,
            headers={"Authorization": f"Bearer {cle}"},
            timeout=TIMEOUT,
        )
        reponse.raise_for_status()
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        if code == 401:
            raise AIUnavailable("Cle API refusee (401).") from exc
        if code == 429:
            raise AIUnavailable("Quota IA depasse (429). Reessaie dans un moment.") from exc
        if code == 404:
            # Le cas le plus frequent, et le plus deroutant : le modele a ete
            # retire du catalogue. Le message donne directement la commande.
            raise AIUnavailable(
                f"Modele {nom_modele!r} introuvable (404). Modeles disponibles : "
                f"GET {base_url()}/models"
            ) from exc
        raise AIUnavailable(f"Le service IA a repondu {code}.") from exc
    except httpx.HTTPError as exc:
        raise AIUnavailable(f"Service IA injoignable : {exc}") from exc

    try:
        contenu = reponse.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise AIUnavailable("Reponse du service IA inattendue.") from exc

    summary, conseils = _parse_reponse(contenu, findings)
    return AiReport(summary=summary, advice=conseils, model=nom_modele)
