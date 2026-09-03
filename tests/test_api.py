"""Tests de l'API HTTP.

TestClient joue le role du navigateur ; respx simule le site distant. Aucun
appel reseau reel n'est fait, sauf la resolution DNS du garde-fou, qui est
neutralisee dans les cas ou elle n'est pas le sujet du test.
"""

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from shhc import api, models

client = TestClient(api.app)


@pytest.fixture(autouse=True)
def _quota_neuf():
    """Remet le compteur a zero : sinon les tests s'epuisent mutuellement."""
    api._appels.clear()
    yield
    api._appels.clear()


@pytest.fixture
def _sans_garde(monkeypatch):
    """Neutralise la resolution DNS quand le sujet du test est ailleurs."""
    monkeypatch.setattr(api.guards, "assert_public_url", lambda url: None)


def test_health():
    reponse = client.get("/api/health")
    assert reponse.status_code == 200
    assert reponse.json()["status"] == "ok"


def test_page_web_servie():
    reponse = client.get("/")
    assert reponse.status_code == 200
    assert "text/html" in reponse.headers["content-type"]


@respx.mock
def test_analyse_complete(_sans_garde):
    respx.get("https://exemple.test").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
            },
        )
    )

    reponse = client.get("/api/check", params={"url": "exemple.test"})

    assert reponse.status_code == 200
    data = reponse.json()
    assert data["url"] == "https://exemple.test"
    assert len(data["findings"]) == 6
    assert data["score"] == 45  # 30 (HSTS) + 15 (nosniff)
    assert data["grade"] == "F"
    assert data["exit_code"] == 2


@respx.mock
def test_site_injoignable_renvoie_502(_sans_garde):
    respx.get("https://exemple.test").mock(side_effect=httpx.ConnectError("nope"))

    reponse = client.get("/api/check", params={"url": "exemple.test"})

    assert reponse.status_code == 502


def test_schema_invalide_renvoie_400():
    reponse = client.get("/api/check", params={"url": "ftp://exemple.test"})
    assert reponse.status_code == 400


def test_adresse_privee_refusee():
    """Le garde-fou anti-SSRF est bien branche sur l'endpoint."""
    reponse = client.get("/api/check", params={"url": "http://169.254.169.254"})

    assert reponse.status_code == 400
    assert "non publique" in reponse.json()["detail"]


def test_quota_depasse_renvoie_429():
    for _ in range(api.RATE_LIMIT):
        client.get("/api/check", params={"url": "http://127.0.0.1"})

    reponse = client.get("/api/check", params={"url": "http://127.0.0.1"})

    assert reponse.status_code == 429


# --------------------------------------------------------------------------
# Recommandations redigees par le modele
#
# Le point a garder : l'IA est optionnelle. Aucun de ses echecs ne doit se
# transformer en erreur HTTP - l'analyse, elle, a reussi.
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _quota_ai_neuf():
    api._appels_ai.clear()
    yield
    api._appels_ai.clear()


@pytest.fixture
def _site(_sans_garde):
    """Un site sans le moindre en-tete : six findings non conformes."""
    with respx.mock:
        respx.get("https://exemple.test").mock(return_value=httpx.Response(200))
        yield


def test_sans_cle_le_rapport_part_quand_meme(_site, monkeypatch):
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    reponse = client.get("/api/check", params={"url": "exemple.test"})

    assert reponse.status_code == 200
    data = reponse.json()
    assert data["ai"] is None
    assert "cle" in data["ai_fallback"].lower()
    # Le client a de quoi afficher : la recommandation statique est intacte.
    assert data["findings"][0]["recommendation"]


def test_echec_du_modele_degrade_sans_erreur(_site, monkeypatch):
    monkeypatch.setenv("SHHC_AI_KEY", "cle-de-test")
    monkeypatch.setattr(
        api.ai, "advise", lambda url, findings: (_ for _ in ()).throw(api.ai.AIUnavailable("panne"))
    )

    reponse = client.get("/api/check", params={"url": "exemple.test"})

    assert reponse.status_code == 200
    assert reponse.json()["ai"] is None
    assert reponse.json()["ai_fallback"] == "panne"


def test_rapport_ia_dans_la_reponse(_site, monkeypatch):
    monkeypatch.setenv("SHHC_AI_KEY", "cle-de-test")
    monkeypatch.setattr(
        api.ai,
        "advise",
        lambda url, findings: models.AiReport(
            summary="Rien n'est configure.",
            advice=[
                models.Advice(
                    header="X-Frame-Options",
                    risk="Le site est encadrable.",
                    action="Poser DENY.",
                    example="X-Frame-Options: DENY",
                    priority="haute",
                )
            ],
            model="modele-de-test",
        ),
    )

    data = client.get("/api/check", params={"url": "exemple.test"}).json()

    assert data["ai_fallback"] is None
    assert data["ai"]["model"] == "modele-de-test"
    assert data["ai"]["advice"][0]["header"] == "X-Frame-Options"


def test_ai_desactivable_par_parametre(_site, monkeypatch):
    """`?ai=false` doit court-circuiter l'appel, pas seulement masquer le retour."""
    appele = False

    def _piege(url, findings):
        nonlocal appele
        appele = True
        raise AssertionError("le modele ne doit pas etre sollicite")

    monkeypatch.setenv("SHHC_AI_KEY", "cle-de-test")
    monkeypatch.setattr(api.ai, "advise", _piege)

    data = client.get("/api/check", params={"url": "exemple.test", "ai": "false"}).json()

    assert appele is False
    assert data["ai"] is None
    assert data["ai_fallback"] is None


def test_quota_ia_degrade_mais_l_analyse_continue(_site, monkeypatch):
    """Le quota IA epuise ne renvoie PAS 429 : seul l'appel au modele saute."""
    monkeypatch.setenv("SHHC_AI_KEY", "cle-de-test")
    monkeypatch.setattr(
        api.ai,
        "advise",
        lambda url, findings: models.AiReport(summary="", advice=[], model="modele-de-test"),
    )

    for _ in range(api.AI_RATE_LIMIT):
        assert client.get("/api/check", params={"url": "exemple.test"}).json()["ai"] is not None

    data = client.get("/api/check", params={"url": "exemple.test"}).json()

    assert data["ai"] is None
    assert "Quota IA" in data["ai_fallback"]


def test_health_annonce_la_disponibilite_de_l_ia(monkeypatch):
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert client.get("/api/health").json()["ai"] is False

    monkeypatch.setenv("SHHC_AI_KEY", "cle-de-test")
    assert client.get("/api/health").json()["ai"] is True
