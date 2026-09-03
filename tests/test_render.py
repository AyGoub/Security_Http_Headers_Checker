"""Tests de la couche d'affichage.

Un seul invariant est verifie ici, mais il est structurant : **la sortie
terminal reste de l'ASCII**. Le reste du rendu (couleurs, largeurs de
colonnes) se juge a l'oeil, pas en test.

Cet invariant ne tenait pas tout seul avant l'arrivee du modele : le texte
etait ecrit a la main, donc deja en ASCII. Le modele, lui, ecrit du francais
accentue et typographique. Sur une console en page de codes 850 - le cas
courant sous Windows - un simple tiret cadratin leve une UnicodeEncodeError
et fait perdre l'analyse entiere.
"""

import io

import pytest
from rich.console import Console

from shhc import render, rules
from shhc.models import Advice, AiReport


@pytest.fixture
def rapport():
    """Un rapport bourre de ponctuation typographique et d'accents."""
    return AiReport(
        summary="Le site n’a aucune en‑tete de securite — c’est critique…",
        advice=[
            Advice(
                header="Strict-Transport-Security",
                risk="Un attaquant peut dégrader la connexion → interception du trafic.",
                action="Déployez HSTS avec un max‑age d’au moins un an.",
                example="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                priority="haute",
            )
        ],
        model="openai/gpt-oss-120b",
    )


def _rendu(rapport, encodage: str) -> str:
    """Rend le rapport dans une console dont la sortie utilise `encodage`.

    `errors="strict"` est le point du test : on veut que l'ecriture ECHOUE si
    un caractere ne passe pas, au lieu d'etre remplace en silence par un `?`.
    """
    tampon = io.TextIOWrapper(io.BytesIO(), encoding=encodage, errors="strict")
    console = Console(file=tampon, width=100, no_color=True, legacy_windows=False)
    findings = rules.analyze({})

    original = render.console
    render.console = console
    try:
        render.render_report("https://exemple.test", findings, 0, "F", rapport)
    finally:
        render.console = original

    tampon.flush()
    return tampon.buffer.getvalue().decode(encodage)


def test_sortie_ascii_pure(rapport):
    """Le rendu ne doit contenir que de l'ASCII, bordures Rich comprises."""
    sortie = _rendu(rapport, "ascii")

    assert sortie.isascii()
    assert "Strict-Transport-Security" in sortie


def test_console_windows_ne_plante_pas(rapport):
    """Le cas reel : une console en page de codes 850 avec errors='strict'."""
    sortie = _rendu(rapport, "cp850")

    assert "max-age=31536000" in sortie


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        ("en‑tete", "en-tete"),
        ("l’apostrophe", "l'apostrophe"),
        ("un — tiret", "un - tiret"),
        ("et ainsi…", "et ainsi..."),
        ("sécurité", "securite"),
        ("espace insecable", "espace insecable"),
        ("flèche → la", "fleche -> la"),
    ],
)
def test_translitteration(entree, attendu):
    assert render._ascii(entree) == attendu


def test_le_json_garde_l_unicode(rapport):
    """La translitteration est propre au terminal : le JSON reste intact.

    Un consommateur machine, et la page web, veulent du francais correct.
    """
    sortie = render.render_json("https://exemple.test", rules.analyze({}), 0, "F", rapport)

    assert "dégrader" in sortie  # accents conserves
    assert "max‑age" in sortie  # trait d'union insecable conserve
    assert "→" in sortie
