"""Tests du garde-fou anti-SSRF.

`localhost` et les adresses litterales ne demandent aucun acces reseau :
elles se resolvent localement.
"""

import pytest

from shhc.guards import BlockedTarget, assert_public_url


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://127.0.0.1",
        "http://127.0.0.1:5432",
        "http://[::1]",
        "http://192.168.1.1",
        "http://10.0.0.5",
        "http://172.16.0.1",
        # L'adresse des metadonnees cloud : la cible classique d'une SSRF.
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_adresses_non_publiques_refusees(url):
    with pytest.raises(BlockedTarget):
        assert_public_url(url)


def test_url_sans_hote_refusee():
    with pytest.raises(BlockedTarget):
        assert_public_url("https://")


def test_domaine_introuvable_refuse():
    with pytest.raises(BlockedTarget):
        assert_public_url("https://domaine-inexistant-42.invalid")


@pytest.mark.parametrize("url", ["https://example.com", "https://1.1.1.1"])
def test_adresses_publiques_acceptees(url):
    """Ne leve pas. Necessite une resolution DNS pour le premier cas."""
    assert_public_url(url)
