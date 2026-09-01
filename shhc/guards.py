"""Garde-fous pour l'exposition publique de l'outil.

Un service qui va chercher une URL fournie par l'utilisateur est une porte
d'entree classique vers le reseau interne de l'hebergeur (SSRF). Ce module
refuse les cibles qui ne sont pas des adresses publiques.
"""

import ipaddress
import socket
from urllib.parse import urlparse


class BlockedTarget(Exception):
    """La cible demandee n'est pas une adresse publique legitime."""


def assert_public_url(url: str) -> None:
    """Verifie que `url` pointe vers une adresse routable sur internet.

    Resout le nom de domaine et refuse si l'une des adresses obtenues est
    privee, locale, de bouclage, ou reservee. Sans ce controle, un visiteur
    pourrait faire interroger `http://169.254.169.254/` (metadonnees du
    fournisseur cloud) ou `http://localhost:5432` par notre serveur.

    Raises:
        BlockedTarget: nom introuvable ou adresse non publique.
    """
    host = urlparse(url).hostname
    if not host:
        raise BlockedTarget("URL sans nom d'hote.")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise BlockedTarget(f"Nom de domaine introuvable : {host}") from exc

    for info in infos:
        adresse = ipaddress.ip_address(info[4][0])
        # is_global est faux pour les plages privees, loopback, link-local,
        # multicast et reservees : un seul test couvre tous les cas.
        if not adresse.is_global:
            raise BlockedTarget(
                f"Adresse non publique refusee : {adresse} (cible {host})."
            )
