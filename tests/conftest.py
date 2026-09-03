"""Configuration commune a toute la suite.

Un seul role, mais il est important : couper l'IA par defaut.

Sans cela, un developpeur qui a `SHHC_AI_KEY` dans son shell verrait les tests
partir vers un service tiers - lentement, en consommant son quota, et avec des
resultats qui dependraient du modele du jour. Les tests qui veulent l'IA la
reactivent explicitement (`monkeypatch.setenv`) et simulent l'endpoint.
"""

from pathlib import Path

import pytest

from shhc import ai

VARIABLES_IA = ("SHHC_AI_KEY", "GROQ_API_KEY", "SHHC_AI_BASE_URL", "SHHC_AI_MODEL")


@pytest.fixture(autouse=True)
def _ia_coupee(monkeypatch):
    """Coupe les deux sources de configuration : l'environnement ET le .env.

    Effacer les variables ne suffirait pas : `ai._charger_env` relirait le
    fichier a la racine du depot - celui du developpeur, avec sa vraie cle.
    On le fait donc pointer vers un fichier inexistant, et on remet le cache
    de chargement a zero pour que chaque test reparte du meme etat.
    """
    for nom in VARIABLES_IA:
        monkeypatch.delenv(nom, raising=False)
    monkeypatch.setattr(ai, "FICHIER_ENV", Path("aucun-fichier-.env-en-test"))
    monkeypatch.setattr(ai, "_env_charge", False)
