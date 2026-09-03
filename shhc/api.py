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

from shhc import __version__, ai, fetch, guards, rules, scoring

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

#: Fenetre glissante de limitation : N requetes par IP et par periode.
RATE_LIMIT = 20
RATE_WINDOW = 60.0

#: Quota distinct, plus serre, pour la redaction par le modele : elle consomme
#: un quota tiers (gratuit mais limite), la ou une analyse d'en-tetes ne coute
#: qu'une requete sortante. Depasser ce seuil degrade vers les recommandations
#: statiques, ce n'est jamais une erreur pour l'appelant.
AI_RATE_LIMIT = 6
AI_RATE_WINDOW = 300.0

_appels: defaultdict[str, deque[float]] = defaultdict(deque)
_appels_ai: defaultdict[str, deque[float]] = defaultdict(deque)

app = FastAPI(
    title="Security HTTP Headers Checker",
    version=__version__,
    description="Note les en-tetes de securite d'une URL publique.",
)


def _consommer(historique: deque[float], limite: int, fenetre: float) -> bool:
    """Fenetre glissante : purge les appels sortis de la fenetre, puis decide.

    Returns:
        True si l'appel est autorise et a ete comptabilise, False sinon.
    """
    maintenant = time.monotonic()
    while historique and maintenant - historique[0] > fenetre:
        historique.popleft()
    if len(historique) >= limite:
        return False
    historique.append(maintenant)
    return True


def _verifier_quota(ip: str) -> None:
    """Limite le nombre d'analyses par IP.

    Chaque appel declenche une requete sortante depuis notre serveur : sans
    quota, le service peut servir de relais pour marteler un tiers.
    """
    if not _consommer(_appels[ip], RATE_LIMIT, RATE_WINDOW):
        raise HTTPException(
            status_code=429,
            detail=f"Trop de requetes. Maximum {RATE_LIMIT} par {int(RATE_WINDOW)} secondes.",
        )


def _rediger(ip: str, url: str, findings: list) -> tuple[dict | None, str | None]:
    """Fait rediger les recommandations, en degradant proprement.

    Trois raisons de ne rien renvoyer : pas de cle configuree, quota IA epuise
    pour cette IP, ou service injoignable. Aucune n'est une erreur : le rapport
    part quand meme, avec les recommandations statiques des findings.

    Returns:
        Le rapport en dict et None, ou None et la raison du repli.
    """
    if not ai.is_configured():
        return None, "Aucune cle API configuree sur ce serveur."

    if not _consommer(_appels_ai[ip], AI_RATE_LIMIT, AI_RATE_WINDOW):
        return None, (
            f"Quota IA atteint ({AI_RATE_LIMIT} par {int(AI_RATE_WINDOW // 60)} minutes)."
        )

    try:
        return asdict(ai.advise(url, findings)), None
    except ai.AIUnavailable as exc:
        return None, str(exc)


@app.get("/api/check")
def check(
    request: Request,
    url: str = Query(..., description="URL a analyser"),
    ai_enabled: bool = Query(True, alias="ai", description="Recommandations redigees par un modele."),
) -> dict:
    """Analyse une URL et renvoie le meme JSON que `shhc --json`.

    La cle `ai` porte le rapport redige par le modele, ou null. Quand elle est
    null, `ai_fallback` dit pourquoi, et les `findings` gardent leur
    recommandation statique : le client a toujours de quoi afficher.
    """
    ip = request.client.host if request.client else "inconnu"
    _verifier_quota(ip)

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

    rapport, repli = _rediger(ip, url_finale, findings) if ai_enabled else (None, None)

    return {
        "url": url_finale,
        "score": score,
        "grade": grade,
        "exit_code": scoring.exit_code(grade),
        "findings": [asdict(finding) for finding in findings],
        "ai": rapport,
        "ai_fallback": repli,
    }


@app.get("/api/health")
def health() -> dict:
    """Sonde utilisee par l'hebergeur pour verifier que le service repond.

    `ai` dit si une cle est configuree : la page web s'en sert pour annoncer
    des recommandations redigees ou statiques avant meme la premiere analyse.
    """
    return {"status": "ok", "version": __version__, "ai": ai.is_configured()}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
