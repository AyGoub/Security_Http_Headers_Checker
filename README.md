# Security HTTP Headers Checker

Outil en ligne de commande qui note les en-têtes de sécurité HTTP d'un site.
Une requête, six en-têtes évalués, une note de 0 à 100 et une lettre A–F.

- Suit les redirections et note **l'URL finale**, celle où le navigateur atterrit.
- Distingue un en-tête absent d'un en-tête présent mais inopérant — un
  `Strict-Transport-Security: max-age=0` est signalé comme `weak`, pas comme `ok`.
- Renvoie un code de sortie exploitable en intégration continue.
- Fait **rédiger les recommandations par un modèle de langage** à partir de la
  valeur réellement observée, plutôt que d'afficher une phrase toute faite.

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e .
```

Ou sans installer le paquet :

```bash
pip install -r requirements.txt
python -m shhc.cli example.com
```

## Utilisation

```bash
shhc mozilla.org           # le https:// est optionnel
shhc --quiet mozilla.org   # 80/100 B
shhc --json mozilla.org    # sortie machine
shhc --no-ai mozilla.org   # recommandations statiques, sans appel au modèle
```

### Exemple de sortie

```
                En-tetes de securite - https://www.mozilla.org/
+-----------------------------------------------------------------------------+
| En-tete                   | Statut  | Valeur       | Points | Raison        |
|---------------------------+---------+--------------+--------+---------------|
| Strict-Transport-Security | ok      | max-age=3153 |  30/30 | Directive     |
|                           |         | 6000         |        | `max-age`     |
|                           |         |              |        | correcte.     |
| Content-Security-Policy   | weak    | font-src     |  15/30 | Politique     |
|                           |         | 'self' ...   |        | permissive.   |
| X-Frame-Options           | ok      | DENY         |  15/15 | Valeur        |
|                           |         |              |        | correcte.     |
| X-Content-Type-Options    | ok      | nosniff      |  15/15 | Valeur        |
|                           |         |              |        | correcte.     |
| Referrer-Policy           | ok      | strict-origi |    5/5 | Valeur        |
|                           |         | n-when-cross |        | correcte.     |
|                           |         | -origin      |        |               |
| Permissions-Policy        | missing | -            |    0/5 | En-tete       |
|                           |         |              |        | absent.       |
+-----------------------------------------------------------------------------+
+---- Note ----+
| B  -  80/100 |
+--------------+

Recommandations (redigees par openai/gpt-oss-120b)
Le site protege bien le transport, mais sa politique de contenu reste
permissive et laisse la porte ouverte au XSS.

+------------- Content-Security-Policy  priorite haute -------------+
|                                                                   |
|  La directive `unsafe-inline` autorise l'execution de tout script  |
|  injecte dans la page : la CSP ne bloque plus le XSS.              |
|                                                                   |
|  A faire : Remplacer les scripts inline par des nonces generes a   |
|  chaque reponse.                                                   |
|                                                                   |
+-------------------------------------------------------------------+
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{ALEA}'
```

Dans un vrai terminal, la table est colorée : vert pour `ok`, jaune pour
`weak`, rouge pour `missing`.

Sans clé API, cette section retombe sur les recommandations statiques portées
par chaque règle — l'outil reste utilisable hors ligne et en intégration
continue.

## La rubrique de notation

| En-tête | Poids | `ok` quand |
|---|---:|---|
| `Strict-Transport-Security` | 30 | `max-age` ≥ 6 mois |
| `Content-Security-Policy` | 30 | politique présente et restrictive |
| `X-Frame-Options` | 15 | `DENY` ou `SAMEORIGIN` |
| `X-Content-Type-Options` | 15 | `nosniff` |
| `Referrer-Policy` | 5 | politique stricte |
| `Permissions-Policy` | 5 | présent et non vide |

Les poids totalisent 100. Un statut `weak` rapporte la moitié des points,
`missing` aucun.

**Grades :** ≥ 90 A · ≥ 80 B · ≥ 70 C · ≥ 60 D · sinon F

## Les recommandations rédigées

Une phrase statique ne peut dire que « ajoutez cet en-tête ». Elle ne sait pas
que votre CSP autorise `unsafe-inline` uniquement sur `script-src`, ni quelle
politique proposer sans casser la page. Le module `shhc/ai.py` envoie l'audit
complet — statut **et valeur observée** — à un modèle, qui renvoie pour chaque
en-tête défaillant le risque concret, l'action à mener, et la ligne à copier.

### Activer

Une clé gratuite suffit, sans carte bancaire :
[console.groq.com/keys](https://console.groq.com/keys).

Puis, au choix : une variable d'environnement, ou un fichier `.env` à la
racine du dépôt — il est lu automatiquement, et couvert par le `.gitignore`.

```bash
export SHHC_AI_KEY=gsk_...     # linux/macOS
$env:SHHC_AI_KEY = "gsk_..."   # PowerShell, session courante
echo SHHC_AI_KEY=gsk_... > .env
shhc mozilla.org
```

L'environnement l'emporte toujours sur le `.env` : sur Render, la variable du
tableau de bord ne peut pas être écrasée par un fichier oublié dans l'image.

Sans clé, tout continue de fonctionner : la note, la table et les
recommandations statiques sont inchangées. `--no-ai` coupe l'appel même quand
une clé est présente.

### Changer de fournisseur

Le dialecte utilisé est `POST /chat/completions`, que parlent la plupart des
services. Changer de fournisseur ne demande que deux variables — aucun code à
toucher. Voir [`.env.example`](.env.example).

| Variable | Défaut | Rôle |
|---|---|---|
| `SHHC_AI_KEY` | — | la clé API (`GROQ_API_KEY` accepté aussi) |
| `SHHC_AI_BASE_URL` | `https://api.groq.com/openai/v1` | racine de l'API |
| `SHHC_AI_MODEL` | `openai/gpt-oss-120b` | le modèle interrogé |

Ces trois variables se lisent aussi depuis `.env`.

**Un modèle retiré du catalogue provoque un `404`.** Les fournisseurs en
retirent régulièrement — c'est arrivé à `llama-3.3-70b-versatile`, le premier
choix par défaut de ce projet. La liste à jour se lit d'un `GET` :

```bash
curl.exe -s https://api.groq.com/openai/v1/models -H "Authorization: Bearer $env:SHHC_AI_KEY"
```

Le message d'erreur du `404` rappelle cette commande.

```bash
# Gemini (palier gratuit)
export SHHC_AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export SHHC_AI_MODEL=gemini-2.5-flash

# Ollama, en local et hors ligne
export SHHC_AI_BASE_URL=http://localhost:11434/v1
export SHHC_AI_MODEL=llama3.1
export SHHC_AI_KEY=peu-importe
```

### Ce que le module refuse de croire

Un modèle peut inventer un en-tête, répondre à côté du format, ou produire un
texte sans fin. La sortie est donc filtrée avant d'atteindre l'affichage :

- une recommandation visant un en-tête **absent de l'audit** est écartée ;
- une recommandation visant un en-tête **déjà conforme** aussi — elle
  contredirait la table affichée juste au-dessus ;
- les doublons sont ignorés, les textes tronqués, les priorités inconnues
  ramenées à `moyenne` ;
- l'ordre d'affichage reste **celui des règles**, du plus critique au moins
  critique, quel que soit l'ordre renvoyé ;
- une action vide retombe sur la phrase statique du `Finding`.

Un site aux six en-têtes conformes ne déclenche aucun appel : il n'y a rien à
recommander.

## Codes de sortie

| Code | Signification |
|---:|---|
| `0` | grade A ou B |
| `1` | grade C ou D |
| `2` | grade F, erreur réseau, ou URL invalide |

Utilisable directement comme portail de qualité :

```bash
shhc https://mon-site.com || echo "en-tetes insuffisants"
```

## Version web et API

Le même moteur est exposé en HTTP : une page à remplir et un point d'entrée
JSON. La logique métier n'est pas dupliquée — `api.py` réutilise `fetch`,
`rules` et `scoring`, exactement comme la CLI.

### Lancer en local

```bash
pip install -r requirements.txt
uvicorn shhc.api:app --reload
```

Puis http://127.0.0.1:8000 pour la page, http://127.0.0.1:8000/docs pour la
documentation interactive de l'API, générée automatiquement par FastAPI.

### Les points d'entrée

| Route | Réponse |
|---|---|
| `GET /` | la page web |
| `GET /api/check?url=<url>` | le rapport en JSON |
| `GET /api/check?url=<url>&ai=false` | le rapport sans appel au modèle |
| `GET /api/health` | sonde de disponibilité, et si l'IA est configurée |
| `GET /docs` | documentation OpenAPI interactive |

```bash
curl "https://<votre-service>.onrender.com/api/check?url=mozilla.org"
```

```json
{
  "url": "https://www.mozilla.org/",
  "score": 80,
  "grade": "B",
  "exit_code": 0,
  "findings": [
    {
      "header": "Strict-Transport-Security",
      "status": "ok",
      "value": "max-age=31536000",
      "weight": 30,
      "points": 30,
      "reason": "Directive `max-age` correcte : 31536000.",
      "recommendation": null
    }
  ],
  "ai": {
    "summary": "Le transport est bien protege, la politique de contenu non.",
    "advice": [
      {
        "header": "Content-Security-Policy",
        "risk": "`unsafe-inline` laisse s'executer tout script injecte.",
        "action": "Remplacer les scripts inline par des nonces.",
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{ALEA}'",
        "priority": "haute"
      }
    ],
    "model": "openai/gpt-oss-120b"
  },
  "ai_fallback": null
}
```

`ai` vaut `null` quand le modèle n'a pas été sollicité ou n'a pas répondu ;
`ai_fallback` dit alors pourquoi, et les `findings` gardent leur
`recommendation` statique — le client a toujours de quoi afficher.

Codes HTTP : `400` URL invalide ou cible refusée · `429` quota dépassé ·
`502` site injoignable. **Un échec de l'IA ne produit jamais d'erreur HTTP** :
l'analyse, elle, a réussi.

### Protections de la version publique

Un service qui va chercher une URL fournie par un visiteur est une porte
d'entrée vers le réseau interne de l'hébergeur. Deux garde-fous :

**Anti-SSRF** (`shhc/guards.py`) — le nom de domaine est résolu avant la
requête, et toute adresse non publique est refusée : bouclage, plages privées,
lien-local. Sans ce contrôle, un visiteur pourrait faire interroger
`http://169.254.169.254/` — les métadonnées du fournisseur cloud, qui
contiennent souvent des identifiants — par notre propre serveur.

**Quota** — 20 analyses par IP et par minute, en fenêtre glissante. Chaque
appel déclenche une requête sortante : sans limite, le service peut servir de
relais pour marteler un tiers.

**Quota IA distinct** — 6 rédactions par IP et par tranche de 5 minutes. La
redaction consomme un quota tiers, gratuit mais limité, là où une analyse ne
coûte qu'une requête sortante. Dépasser ce seuil dégrade vers les
recommandations statiques ; ce n'est pas une erreur pour l'appelant.

*Limite connue :* le contrôle anti-SSRF résout le nom, puis httpx le résout à
nouveau. Un attaquant contrôlant un serveur DNS pourrait renvoyer une adresse
publique au premier appel et une adresse privée au second (*DNS rebinding*).
Fermer cette fenêtre demande de résoudre une seule fois et de se connecter à
l'IP validée.

## Déploiement sur Render.com

Le fichier [`render.yaml`](render.yaml) décrit le service. Deux façons de
procéder :

**Avec le blueprint** — sur Render.com, *New* → *Blueprint*, sélectionner ce
dépôt. Tout est lu depuis `render.yaml`, il n'y a rien à saisir.

**À la main** — *New* → *Web Service*, puis :

| Champ | Valeur |
|---|---|
| Runtime | Python 3 |
| Build command | `pip install -r requirements.txt` |
| Start command | `uvicorn shhc.api:app --host 0.0.0.0 --port $PORT` |
| Health check path | `/api/health` |

`$PORT` est fourni par Render.com : il faut l'utiliser tel quel, un port en dur
empêche le service de démarrer. `--host 0.0.0.0` est également obligatoire —
avec l'adresse par défaut, le conteneur n'accepterait aucune connexion externe.

Dans les deux cas, ajouter la variable `SHHC_AI_KEY` dans *Environment* pour
activer les recommandations rédigées. `render.yaml` la déclare en `sync: false`
— Render la demande au déploiement, elle ne transite jamais par le dépôt. Sans
elle, le service démarre normalement et sert les recommandations statiques.

Sur le plan gratuit, le service s'endort après quinze minutes d'inactivité et
met une trentaine de secondes à redémarrer à la visite suivante.

## Stack technique

**Python 3.11** (compatible 3.10+). Aucune dependance lourde : chaque
bibliotheque repond a un besoin precis.

| Rôle | Bibliothèque | Version | Pourquoi celle-ci |
|---|---|---|---|
| Client HTTP | [httpx](https://www.python-httpx.org/) | 0.28 | suivi de redirections explicite, timeouts par défaut, API moderne |
| Affichage terminal | [rich](https://rich.readthedocs.io/) | 15.0 | tables, panneaux et couleurs sans gérer les codes ANSI à la main |
| Interface CLI | [typer](https://typer.tiangolo.com/) | 0.27 | les options se déclarent par annotations de type, `--help` généré |
| API web | [fastapi](https://fastapi.tiangolo.com/) | 0.141 | validation par annotations, documentation OpenAPI generee |
| Serveur ASGI | [uvicorn](https://www.uvicorn.org/) | 0.52 | serveur de production leger, attendu par Render.com |
| Tests | [pytest](https://docs.pytest.org/) | 9.1 | paramétrage des cas, sortie d'échec lisible |
| Simulation HTTP | [respx](https://lundberg.github.io/respx/) | 0.23 | intercepte les requêtes httpx : la suite tourne sans réseau |

Les versions ci-dessus sont celles testées. `requirements.txt` déclare des
minimums (`httpx>=0.27`), pas des versions figées.

**L'IA n'ajoute aucune dépendance.** Le dialecte `POST /chat/completions` est
du JSON sur HTTP : `httpx`, déjà présent pour aller chercher les en-têtes,
suffit. Installer le SDK d'un fournisseur aurait ajouté un paquet, et surtout
attaché le projet à ce fournisseur — alors que le but était l'inverse.

### Les choix qui structurent le code

**Pourquoi httpx et pas requests.** Le suivi des redirections doit être un choix
visible, pas un comportement implicite : c'est le cœur de la règle « noter l'URL
finale ». httpx demande `follow_redirects=True` explicitement, là où requests le
fait en silence. Il impose aussi un timeout explicite, ce qui évite l'oubli
classique qui laisse un programme suspendu indéfiniment.

**Pourquoi respx.** Tester une couche réseau contre de vrais sites rend la suite
lente, dépendante de la connexion, et instable — un site qui change sa
configuration casse un test sans que le code ait bougé. respx remplace la couche
transport de httpx (`httpcore`) et sert des réponses déclarées à l'avance. Tout
le code httpx s'exécute réellement, y compris le suivi des redirections ; seule
l'ouverture de la socket est court-circuitée. Un appel réseau non prévu fait
échouer le test au lieu de sortir sur internet.

**Sortie ASCII uniquement.** La console Windows utilise couramment la page de
codes 850, qui ne contient ni tiret cadratin, ni puce, ni points de suspension
Unicode. Ces caractères s'afficheraient en `?`. Comme l'outil vise aussi les
logs d'intégration continue, rarement en UTF-8, tout le rendu reste en ASCII.
Les couleurs, elles, fonctionnent partout.

Cet invariant tenait tout seul tant que les textes étaient écrits à la main.
Le modèle, lui, produit du français accentué et typographique — apostrophes
courbes, traits d'union insécables, tirets cadratins. Un `sys.stdout` en
cp1252 lève une `UnicodeEncodeError` sur l'un d'eux, et l'analyse entière est
perdue pour un caractère de ponctuation. `render._ascii()` translitère donc le
texte du modèle, **dans la couche terminal seulement** : la sortie JSON et la
page web sont en UTF-8 et gardent le texte intact.

## Architecture

```
shhc/
  models.py     Finding, Advice, AiReport + les constantes   102 lignes
  fetch.py      requête réseau, redirections, erreurs         60
  rules.py      les 6 règles de notation -> Finding          307
  scoring.py    somme pondérée -> score + grade               49
  ai.py         rédaction des recommandations par un modèle  266
  render.py     table Rich, panel de note, recommandations   196
  cli.py        orchestration et codes de sortie              83
  api.py        API HTTP + page web (FastAPI)                155
  guards.py     garde-fou anti-SSRF                           44
web/
  index.html    la page, sans dependance externe
```

### Le flux

```
   URL saisie
       |
   cli.py ............ normalise, orchestre, choisit le code de sortie
       |
   fetch.py .......... 1 requête -> (URL finale, en-têtes en minuscules)
       |
   rules.py .......... 6 règles -> list[Finding]
       |
   scoring.py ........ somme des points -> score + grade
       |
   ai.py ............. findings + valeurs -> AiReport   (optionnel)
       |               echec -> None, on garde le statique
   render.py ......... table + panel + recommandations
```

`ai.py` est la seule couche qui puisse échouer sans conséquence : son retour
est un `AiReport | None`, et `None` est un cas nominal, pas une erreur.

### Le pivot : `Finding`

Une seule dataclass circule entre les couches. `rules.py` en produit une liste,
`scoring.py` la consomme, `ai.py` la commente, `render.py` l'affiche — aucune
couche ne connaît les autres.

```python
@dataclass
class Finding:
    header: str            # "Strict-Transport-Security"
    status: Status         # "ok" | "weak" | "missing"
    value: str | None      # la valeur brute reçue, None si absent
    weight: int            # 30, 15 ou 5
    points: int            # poids x facteur du statut
    reason: str            # pourquoi ce statut, en une ligne
    recommendation: str | None
```

`Finding.recommendation` n'a pas disparu avec l'arrivée du modèle : c'est le
filet. Il est toujours produit, sans réseau ni clé, et reprend la main dès que
la rédaction échoue. `Advice` est la version enrichie, jamais l'unique version.

### Deux règles de conception

**Les modules purs d'abord.** `rules.py` et `scoring.py` ne font ni réseau ni
affichage : une fonction reçoit un dictionnaire, renvoie un objet. Ils
constituent 356 des 1262 lignes du paquet et se testent sans simuler quoi que
ce soit — d'ou les 103 tests qui s'executent en quelques secondes.

**L'IA est un confort, jamais un point de passage.** Un service tiers finit
toujours par tomber, expirer, ou changer de format. `ai.py` ne lève qu'un seul
type d'erreur, `AIUnavailable`, parce que l'appelant n'a qu'une décision à
prendre : retomber sur le statique. Aucun appelant ne propage cet échec —
la CLI prévient sur `stderr` et garde son code de sortie, l'API renvoie `200`
avec `ai: null`. C'est aussi ce qui rend la suite de tests hermétique :
`tests/conftest.py` efface les variables d'environnement de l'IA, une clé
présente dans le shell du développeur ne peut pas faire sortir les tests sur
internet.

**La normalisation en un seul endroit.** Les en-têtes HTTP étant insensibles à
la casse, `fetch.py` met toutes les clés en minuscules à la sortie de la
requête. Tout le code en aval peut alors supposer des clés en minuscules, au
lieu que chaque règle teste plusieurs orthographes.

## Développement

```bash
pip install -r requirements-dev.txt
pytest                                    # toute la suite : 119 tests
pytest tests/test_rules.py -v             # un fichier
pytest tests/test_rules.py::TestHSTS      # une classe
pytest -k hsts                            # par motif
pytest --lf                               # rejouer les derniers échecs
```

### Couverture des tests

| Fichier | Ce qu'il vérifie |
|---|---|
| `test_models.py` | les invariants : poids totalisant 100, seuils décroissants |
| `test_fetch.py` | normalisation d'URL, casse des clés, redirections, 403, timeouts |
| `test_rules.py` | les 6 règles, dont `max-age=0` classé `weak` et non `ok` |
| `test_scoring.py` | les bornes exactes des grades (90 → A, 89 → B) et les codes de sortie |
| `test_guards.py` | le refus des adresses privées, locales et de métadonnées cloud |
| `test_render.py` | la garantie ASCII de la sortie terminal, face à un texte accentué |
| `test_api.py` | les routes HTTP, les codes 400/429/502, la page servie et le repli quand l'IA manque |
| `test_ai.py` | le contrat de `ai.py` : hallucinations écartées, erreurs converties, lecture du `.env`, aucun appel réseau réel |
