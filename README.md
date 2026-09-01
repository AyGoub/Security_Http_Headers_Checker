# Security HTTP Headers Checker

Outil en ligne de commande qui note les en-têtes de sécurité HTTP d'un site.
Une requête, six en-têtes évalués, une note de 0 à 100 et une lettre A–F.

- Suit les redirections et note **l'URL finale**, celle où le navigateur atterrit.
- Distingue un en-tête absent d'un en-tête présent mais inopérant — un
  `Strict-Transport-Security: max-age=0` est signalé comme `weak`, pas comme `ok`.
- Renvoie un code de sortie exploitable en intégration continue.

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

Recommandations
  * Content-Security-Policy - Retirer `unsafe-inline`, `unsafe-eval`.
  * Permissions-Policy - Ajouter l'en-tete `Permissions-Policy`.
```

Dans un vrai terminal, la table est colorée : vert pour `ok`, jaune pour
`weak`, rouge pour `missing`.

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

## Stack technique

**Python 3.11** (compatible 3.10+). Le projet n'utilise aucune dépendance
lourde : quatre bibliothèques, chacune pour une raison précise.

| Rôle | Bibliothèque | Version | Pourquoi celle-ci |
|---|---|---|---|
| Client HTTP | [httpx](https://www.python-httpx.org/) | 0.28 | suivi de redirections explicite, timeouts par défaut, API moderne |
| Affichage terminal | [rich](https://rich.readthedocs.io/) | 15.0 | tables, panneaux et couleurs sans gérer les codes ANSI à la main |
| Interface CLI | [typer](https://typer.tiangolo.com/) | 0.27 | les options se déclarent par annotations de type, `--help` généré |
| Tests | [pytest](https://docs.pytest.org/) | 9.1 | paramétrage des cas, sortie d'échec lisible |
| Simulation HTTP | [respx](https://lundberg.github.io/respx/) | 0.23 | intercepte les requêtes httpx : la suite tourne sans réseau |

Les versions ci-dessus sont celles testées. `requirements.txt` déclare des
minimums (`httpx>=0.27`), pas des versions figées.

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

## Architecture

```
shhc/
  models.py     Finding + les constantes (poids, seuils)      48 lignes
  fetch.py      requête réseau, redirections, erreurs         43
  rules.py      les 6 règles de notation -> Finding          274
  scoring.py    somme pondérée -> score + grade               37
  render.py     table Rich, panel de note, recommandations   100
  cli.py        orchestration et codes de sortie              46
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
   render.py ......... table + panel + recommandations
```

### Le pivot : `Finding`

Une seule dataclass circule entre les couches. `rules.py` en produit une liste,
`scoring.py` la consomme, `render.py` l'affiche — aucune couche ne connaît les
autres.

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

### Deux règles de conception

**Les modules purs d'abord.** `rules.py` et `scoring.py` ne font ni réseau ni
affichage : une fonction reçoit un dictionnaire, renvoie un objet. Ils
constituent 311 des 548 lignes du paquet et se testent sans simuler quoi que ce
soit — d'où les 61 tests qui s'exécutent en moins de 3 secondes.

**La normalisation en un seul endroit.** Les en-têtes HTTP étant insensibles à
la casse, `fetch.py` met toutes les clés en minuscules à la sortie de la
requête. Tout le code en aval peut alors supposer des clés en minuscules, au
lieu que chaque règle teste plusieurs orthographes.

## Développement

```bash
pip install -r requirements-dev.txt
pytest                                    # toute la suite : 61 tests
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
