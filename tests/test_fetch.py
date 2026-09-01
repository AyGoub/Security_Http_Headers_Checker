"""Tests de la couche reseau.

Les tests de `normalize_url` sont purs. Ceux de `fetch` utilisent respx pour
simuler les reponses HTTP : aucun appel reseau reel n'est fait.
"""

import httpx
import pytest
import respx

from shhc.fetch import USER_AGENT, FetchError, fetch, normalize_url


@pytest.mark.parametrize(
    ("saisie", "attendu"),
    [
        ("https://example.com", "https://example.com"),
        ("http://example.com", "http://example.com"),
        ("example.com", "https://example.com"),
        ("  example.com  ", "https://example.com"),
        ("example.com/path?a=1", "https://example.com/path?a=1"),
    ],
)
def test_normalisation(saisie, attendu):
    assert normalize_url(saisie) == attendu


@pytest.mark.parametrize("saisie", ["", "   ", "ftp://example.com", "file:///etc/passwd"])
def test_entrees_refusees(saisie):
    with pytest.raises(ValueError):
        normalize_url(saisie)


@respx.mock
def test_cles_normalisees_en_minuscules():
    """Le serveur envoie 'X-Frame-Options', on doit pouvoir lire la cle en minuscules.

    Les en-tetes HTTP sont insensibles a la casse : sans cette normalisation,
    chaque regle devrait tester plusieurs orthographes de la meme cle.
    """
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers={"X-Frame-Options": "DENY"})
    )

    _, headers = fetch("https://example.com")

    assert headers["x-frame-options"] == "DENY"
    assert "X-Frame-Options" not in headers


@respx.mock
def test_url_finale_apres_redirection():
    """On note la page d'arrivee, pas celle demandee.

    Une redirection 301 ne porte aucun en-tete de securite utile : c'est la
    page finale que le navigateur affiche, donc la seule a evaluer.
    """
    respx.get("https://example.com").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.example.com/"})
    )
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(200, headers={"X-Frame-Options": "DENY"})
    )

    final_url, headers = fetch("https://example.com")

    assert final_url == "https://www.example.com/"
    assert headers["x-frame-options"] == "DENY"


@respx.mock
def test_403_ne_leve_pas():
    """Un code d'erreur HTTP n'est pas un echec pour notre outil.

    Certains sites derriere un pare-feu applicatif repondent 403 a un client
    inconnu, tout en renvoyant leurs en-tetes de securite. On les note quand meme.
    """
    respx.get("https://example.com").mock(
        return_value=httpx.Response(403, headers={"X-Content-Type-Options": "nosniff"})
    )

    _, headers = fetch("https://example.com")

    assert headers["x-content-type-options"] == "nosniff"


@respx.mock
def test_user_agent_identifiable():
    """Une requete polie s'annonce : le User-Agent doit partir avec la requete."""
    route = respx.get("https://example.com").mock(return_value=httpx.Response(200))

    fetch("https://example.com")

    envoye = route.calls.last.request
    assert envoye.headers["user-agent"] == USER_AGENT


@respx.mock
def test_timeout_devient_fetcherror():
    """Aucune exception httpx ne doit remonter jusqu'a l'utilisateur."""
    respx.get("https://example.com").mock(side_effect=httpx.ConnectTimeout("trop long"))

    with pytest.raises(FetchError):
        fetch("https://example.com")


@respx.mock
def test_domaine_injoignable_devient_fetcherror():
    """Meme chose pour une erreur DNS ou TLS."""
    respx.get("https://example.invalid").mock(side_effect=httpx.ConnectError("dns"))

    with pytest.raises(FetchError):
        fetch("https://example.invalid")
