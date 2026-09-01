"""Tests du calcul de note.

Specification executable du MVP 3. Retirer le `pytestmark` une fois
`scoring` implemente.
"""

import pytest

from shhc import scoring
from shhc.models import WEIGHTS, Finding

pytestmark = pytest.mark.xfail(reason="MVP 3 pas encore implemente", strict=False)


def _finding(header: str, status: str, points: int) -> Finding:
    return Finding(
        header=header,
        status=status,
        value=None,
        weight=WEIGHTS[header],
        points=points,
        reason="test",
    )


def test_tout_ok_donne_cent():
    findings = [_finding(h, "ok", w) for h, w in WEIGHTS.items()]
    assert scoring.score(findings) == 100


def test_rien_donne_zero():
    findings = [_finding(h, "missing", 0) for h in WEIGHTS]
    assert scoring.score(findings) == 0


@pytest.mark.parametrize(
    ("valeur", "lettre"),
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (70, "C"),
        (69, "D"),
        (60, "D"),
        (59, "F"),
        (0, "F"),
    ],
)
def test_bornes_des_grades(valeur, lettre):
    """Les bornes exactes : 90 est un A, 89 est un B."""
    assert scoring.grade(valeur) == lettre


@pytest.mark.parametrize(
    ("lettre", "code"),
    [("A", 0), ("B", 0), ("C", 1), ("D", 1), ("F", 2)],
)
def test_codes_de_sortie(lettre, code):
    assert scoring.exit_code(lettre) == code
