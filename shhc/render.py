"""Affichage Rich : table des findings, panel de note, recommandations.

Seul module autorise a ecrire sur la sortie standard.

MVP 4 - a implementer.
"""

from rich.console import Console

from shhc.models import Finding

console = Console()

#: Couleur associee a chaque statut, utilisee dans toute la sortie.
STATUS_STYLE: dict[str, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

#: Au-dela, la valeur d'un en-tete est tronquee dans la table. Une CSP
#: depasse facilement 400 caracteres et ferait exploser la mise en page.
MAX_VALUE_WIDTH = 48


def render_report(url: str, findings: list[Finding], score_value: int, grade_value: str) -> None:
    """Affiche le rapport complet.

    Trois blocs, dans cet ordre :
      1. une Table : En-tete | Statut | Valeur | Points | Raison
      2. un Panel : le score et la lettre, borde de la couleur du grade
      3. la liste des recommandations, une par finding non-ok

    `url` est l'URL FINALE apres redirections, a afficher telle quelle pour
    que l'utilisateur voie quelle page a reellement ete notee.
    """
    raise NotImplementedError("MVP 4")


def render_json(url: str, findings: list[Finding], score_value: int, grade_value: str) -> str:
    """Meme rapport, en JSON, pour consommation machine.

    MVP 5.
    """
    raise NotImplementedError("MVP 5")
