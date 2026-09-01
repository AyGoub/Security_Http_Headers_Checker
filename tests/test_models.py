"""Invariants du modele. Ces tests passent des maintenant."""

from shhc.models import GRADE_THRESHOLDS, STATUS_FACTOR, WEIGHTS


def test_les_poids_totalisent_cent():
    """Sans ca, le score n'est plus sur 100 et il faudrait normaliser."""
    assert sum(WEIGHTS.values()) == 100


def test_noms_en_tetes_en_minuscules():
    """`fetch` normalise les cles en minuscules : les regles doivent suivre."""
    assert all(name == name.lower() for name in WEIGHTS)


def test_statuts_couverts():
    assert set(STATUS_FACTOR) == {"ok", "weak", "missing"}


def test_seuils_decroissants():
    seuils = [seuil for seuil, _ in GRADE_THRESHOLDS]
    assert seuils == sorted(seuils, reverse=True)
