"""Note et grade a partir des findings.

Module PUR, comme `rules`. Aucune I/O.

MVP 3 - a implementer.
"""

from shhc.models import Finding


def score(findings: list[Finding]) -> int:
    """Somme les points des findings.

    Les poids totalisent 100, donc cette somme EST le score sur 100 :
    aucune normalisation n'est necessaire.
    """
    return sum(f.points for f in findings)


def grade(score_value: int) -> str:
    """Traduit un score 0-100 en lettre A-F.

    Seuils : >=90 A, >=80 B, >=70 C, >=60 D, sinon F.
    Attention aux bornes : 90 doit donner A, 89 doit donner B.
    """
    if score_value >= 90:
        return "A"
    elif score_value >= 80:
        return "B"
    elif score_value >= 70:
        return "C"
    elif score_value >= 60:
        return "D"
    else:
        return "F"


def exit_code(grade_value: str) -> int:
    """Code de sortie pour la CI.

    0 pour A ou B, 1 pour C ou D, 2 pour F.
    Les erreurs reseau renvoient aussi 2, mais c'est `cli` qui s'en charge.
    """
    if grade_value in ("A", "B"):
        return 0
    elif grade_value in ("C", "D"):
        return 1
    else:
        return 2
