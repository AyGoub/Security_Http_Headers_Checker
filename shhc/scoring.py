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
    raise NotImplementedError("MVP 3")


def grade(score_value: int) -> str:
    """Traduit un score 0-100 en lettre A-F.

    Seuils : >=90 A, >=80 B, >=70 C, >=60 D, sinon F.
    Attention aux bornes : 90 doit donner A, 89 doit donner B.
    """
    raise NotImplementedError("MVP 3")


def exit_code(grade_value: str) -> int:
    """Code de sortie pour la CI.

    0 pour A ou B, 1 pour C ou D, 2 pour F.
    Les erreurs reseau renvoient aussi 2, mais c'est `cli` qui s'en charge.
    """
    raise NotImplementedError("MVP 3")
