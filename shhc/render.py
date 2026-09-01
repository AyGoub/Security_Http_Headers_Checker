"""Affichage Rich : table des findings, panel de note, recommandations.

Seul module autorise a ecrire sur la sortie standard.
"""

import json
from dataclasses import asdict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shhc.models import Finding

console = Console()

#: Couleur associee a chaque statut, utilisee dans toute la sortie.
STATUS_STYLE: dict[str, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

#: Couleur du panel de note selon le grade obtenu.
GRADE_STYLE: dict[str, str] = {
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "yellow",
    "F": "red",
}

#: Au-dela, la valeur d'un en-tete est tronquee dans la table. Une CSP
#: depasse facilement 400 caracteres et ferait exploser la mise en page.
MAX_VALUE_WIDTH = 48

#: Meme garde-fou pour la colonne Raison : une regle qui cite la valeur
#: fautive dans son message ne doit pas pouvoir deformer la table.
MAX_REASON_WIDTH = 60


def _shorten(text: str | None, limit: int) -> str:
    """Raccourcit un texte trop long et gere l'absence de valeur.

    Un en-tete manquant a une valeur None : on affiche un tiret plutot que
    le mot "None", qui n'a pas de sens pour l'utilisateur.
    """
    if not text:
        return "-"
    text = " ".join(text.split())  # replie les retours a la ligne eventuels
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def render_report(url: str, findings: list[Finding], score_value: int, grade_value: str) -> None:
    """Affiche le rapport complet.

    Trois blocs, dans cet ordre :
      1. une Table : En-tete | Statut | Valeur | Points | Raison
      2. un Panel : le score et la lettre, borde de la couleur du grade
      3. la liste des recommandations, une par finding non-ok

    `url` est l'URL FINALE apres redirections, affichee telle quelle pour
    que l'utilisateur voie quelle page a reellement ete notee.
    """
    table = Table(
        title=f"En-tetes de securite - {url}",
        title_style="bold",
        box=box.ROUNDED,
        header_style="bold",
    )
    table.add_column("En-tete", style="bold blue", no_wrap=True)
    table.add_column("Statut")
    table.add_column("Valeur", overflow="fold")
    table.add_column("Points", justify="right")
    table.add_column("Raison", style="grey70", overflow="fold")

    for finding in findings:
        # La couleur depend du statut de CHAQUE ligne : elle se pose donc
        # dans la cellule, pas sur la colonne.
        style = STATUS_STYLE[finding.status]
        table.add_row(
            finding.header,
            f"[{style}]{finding.status}[/{style}]",
            _shorten(finding.value, MAX_VALUE_WIDTH),
            f"{finding.points}/{finding.weight}",
            _shorten(finding.reason, MAX_REASON_WIDTH),
        )

    console.print(table)

    style = GRADE_STYLE[grade_value]
    console.print(
        Panel(
            f"[bold {style}]{grade_value}[/bold {style}]  -  {score_value}/100",
            title="Note",
            border_style=style,
            expand=False,
        )
    )

    problemes = [finding for finding in findings if finding.status != "ok"]
    if not problemes:
        console.print("[green]Aucune recommandation : tous les en-tetes sont corrects.[/green]")
        return

    console.print("\n[bold]Recommandations[/bold]")
    for finding in problemes:
        style = STATUS_STYLE[finding.status]
        console.print(
            f"  [{style}]*[/{style}] [bold]{finding.header}[/bold] - {finding.recommendation}"
        )


def render_json(url: str, findings: list[Finding], score_value: int, grade_value: str) -> str:
    """Meme rapport, en JSON, pour consommation machine.

    Les valeurs ne sont PAS tronquees ici : la troncature sert la lisibilite
    d'une table, elle n'a pas lieu d'etre dans une sortie destinee a un script.
    """
    return json.dumps(
        {
            "url": url,
            "score": score_value,
            "grade": grade_value,
            "findings": [asdict(finding) for finding in findings],
        },
        indent=2,
        ensure_ascii=False,
    )
