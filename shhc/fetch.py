"""Couche reseau : une seule requete, polie, vers l'URL cible.

MVP 1 - a implementer.
"""

import httpx

from shhc import __version__

USER_AGENT = f"shhc/{__version__} (Security HTTP Headers Checker)"
TIMEOUT = 10.0


class FetchError(Exception):
    """L'URL n'a pas pu etre atteinte. Message deja lisible par un humain."""


def normalize_url(url: str) -> str:
    """Complete une URL saisie a la main.

    Prefixe `https://` si aucun schema n'est fourni, pour que
    `shhc example.com` fonctionne comme `shhc https://example.com`.

    Raises:
        ValueError: si l'URL est vide ou utilise un schema non HTTP.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL vide.")
    if url.startswith(("http://", "https://")):
        return url
    if "://" in url:
        schema = url.split("://", 1)[0]
        raise ValueError(f"Schema non supporte : {schema!r}. Utilise http ou https.")
    return f"https://{url}"


def fetch(url: str) -> tuple[str, dict[str, str]]:
    """Recupere les en-tetes de reponse de `url`.

    Suit les redirections et renvoie l'URL FINALE : c'est la page ou le
    navigateur atterrit vraiment, donc la seule qu'il soit pertinent de noter.
    Les cles des en-tetes sont normalisees en minuscules ici, une bonne fois
    pour toutes, parce que les en-tetes HTTP sont insensibles a la casse.

    Returns:
        (url_finale, en-tetes en minuscules)

    Raises:
        FetchError: probleme reseau, DNS, TLS ou timeout.
    """
    try:
        request = httpx.get(url, 
follow_redirects=True, timeout=TIMEOUT,
                            headers={"User-Agent": USER_AGENT})
        return str(request.url), {k.lower(): v for k, v in request.headers.items()}
    except httpx.RequestError as e:
        raise FetchError(f"Erreur reseau : {e}") from e
    
    
