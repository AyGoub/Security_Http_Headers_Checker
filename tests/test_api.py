"""Tests de l'API HTTP.

TestClient joue le role du navigateur ; respx simule le site distant. Aucun
appel reseau reel n'est fait, sauf la resolution DNS du garde-fou, qui est
neutralisee dans les cas ou elle n'est pas le sujet du test.
"""

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from shhc import api

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
