"""API HTTP et page web pour l'analyseur d'en-tetes.

La logique metier est celle de la CLI : ce module ne fait qu'exposer
fetch -> rules -> scoring sur HTTP, et servir la page statique.
"""

import time
from collections import defaultdict, deque
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from shhc import __version__, fetch, guards, rules, scoring

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

#: Fenetre glissante de limitation : N requetes par IP et par periode.
RATE_LIMIT = 20
RATE_WINDOW = 60.0

_appels: defaultdict[str, deque[float]] = defaultdict(deque)

app = FastAPI(
    title="Security HTTP Headers Checker",
    version=__version__,
    description="Note les en-tetes de securite d'une URL publique.",
)


def _verifier_quota(ip: str) -> None:
    """Limite le nombre d'analyses par IP.

    Chaque appel declenche une requete sortante depuis notre serveur : sans
    quota, le service peut servir de relais pour marteler un tiers.
    """
    maintenant = time.monotonic()
    historique = _appels[ip]
    while historique and maintenant - historique[0] > RATE_WINDOW:
        historique.popleft()
    if len(historique) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de requetes. Maximum {RATE_LIMIT} par {int(RATE_WINDOW)} secondes.",
        )
    historique.append(maintenant)


@app.get("/api/check")
def check(request: Request, url: str = Query(..., description="URL a analyser")) -> dict:
    """Analyse une URL et renvoie le meme JSON que `shhc --json`."""
    _verifier_quota(request.client.host if request.client else "inconnu")

    try:
        cible = fetch.normalize_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        guards.assert_public_url(cible)
    except guards.BlockedTarget as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        url_finale, headers = fetch.fetch(cible)
    except fetch.FetchError as exc:
        raise HTTPException(status_code=502, detail=f"Impossible d'atteindre {cible} : {exc}") from exc

    findings = rules.analyze(headers)
    score = scoring.score(findings)
    grade = scoring.grade(score)

    return {
        "url": url_finale,
        "score": score,
        "grade": grade,
        "exit_code": scoring.exit_code(grade),
        "findings": [asdict(finding) for finding in findings],
    }


@app.get("/api/health")
def health() -> dict:
    """Sonde utilisee par l'hebergeur pour verifier que le service repond."""
    return {"status": "ok", "version": __version__}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
