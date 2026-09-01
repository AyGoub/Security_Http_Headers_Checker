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

## Développement

```bash
pip install -r requirements-dev.txt
pytest                              # toute la suite
pytest tests/test_rules.py -v       # un fichier
pytest -k hsts                      # par motif
```

### Architecture

```
shhc/
  models.py     Finding + les constantes (poids, seuils)
  fetch.py      requête réseau, redirections, erreurs
  rules.py      les 6 règles de notation -> Finding
  scoring.py    somme pondérée -> score + grade
  render.py     table Rich, panel de note, recommandations
  cli.py        orchestration et codes de sortie
```

`rules.py` et `scoring.py` sont des modules purs : ni réseau, ni affichage.
C'est ce qui permet de les tester sans simuler quoi que ce soit. Les tests de
`fetch.py` utilisent `respx`, qui intercepte les requêtes au niveau de
`httpcore` — aucun appel réseau réel n'est fait pendant la suite de tests.
