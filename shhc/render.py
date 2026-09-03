"""Affichage Rich : table des findings, panel de note, recommandations.

Seul module autorise a ecrire sur la sortie standard.
"""

import json
import unicodedata
from dataclasses import asdict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from shhc.models import AiReport, Finding

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

#: Couleur de la pastille de priorite portee par un conseil du modele.
PRIORITY_STYLE: dict[str, str] = {
    "haute": "red",
    "moyenne": "yellow",
    "basse": "cyan",
}

#: Au-dela, la valeur d'un en-tete est tronquee dans la table. Une CSP
#: depasse facilement 400 caracteres et ferait exploser la mise en page.
MAX_VALUE_WIDTH = 48

#: Meme garde-fou pour la colonne Raison : une regle qui cite la valeur
#: fautive dans son message ne doit pas pouvoir deformer la table.
MAX_REASON_WIDTH = 60


#: Ponctuation typographique que le modele produit spontanement et que la page
#: de codes 850 ne contient pas. La translitteration automatique la supprimerait
#: purement et simplement : on choisit donc l'equivalent ASCII a la main.
REMPLACEMENTS = str.maketrans(
    {
        "‑": "-",  # trait d'union insecable
        "–": "-",  # tiret demi-cadratin
        "—": "-",  # tiret cadratin
        "‘": "'",
        "’": "'",  # apostrophe typographique
        "“": '"',
        "”": '"',
        "…": "...",
        " ": " ",  # espace insecable
        " ": " ",  # espace fine insecable
        "→": "->",
    }
)


def _ascii(text: str) -> str:
    """Ramene le texte du modele a de l'ASCII affichable partout.

    Le reste de l'outil est ecrit en ASCII pour une raison : la console
    Windows utilise couramment la page de codes 850, et les journaux
    d'integration continue sont rarement en UTF-8. Un `sys.stdout` en cp1252
    leve une `UnicodeEncodeError` sur un simple tiret cadratin - l'analyse
    entiere se perdrait pour un caractere de ponctuation.

    Le modele, lui, ecrit du francais accentue et typographique. On le
    translitere ici, dans la couche terminal, et nulle part ailleurs : la
    sortie JSON et la page web sont en UTF-8 et gardent le texte intact.
    """
    text = text.translate(REMPLACEMENTS)
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


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


def render_report(
    url: str,
    findings: list[Finding],
    score_value: int,
    grade_value: str,
    report: AiReport | None = None,
) -> None:
    """Affiche le rapport complet.

    Trois blocs, dans cet ordre :
      1. une Table : En-tete | Statut | Valeur | Points | Raison
      2. un Panel : le score et la lettre, borde de la couleur du grade
      3. les recommandations, une par finding non-ok

    `url` est l'URL FINALE apres redirections, affichee telle quelle pour
    que l'utilisateur voie quelle page a reellement ete notee.

    `report` est le rapport redige par le modele. Fourni, il remplace les
    recommandations statiques ; absent, celles-ci prennent le relais - la
    sortie n'est donc jamais vide, meme sans cle API.
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

    if report is not None and report.advice:
        _render_ai(report)
        return

    console.print("\n[bold]Recommandations[/bold]")
    for finding in problemes:
        style = STATUS_STYLE[finding.status]
        console.print(
            f"  [{style}]*[/{style}] [bold]{finding.header}[/bold] - {finding.recommendation}"
        )


def _render_ai(report: AiReport) -> None:
    """Affiche les recommandations redigees par le modele.

    Un Panel par conseil : le risque en texte courant, puis l'action a mener.
    Le titre porte la priorite, pour que l'oeil trouve les urgences sans avoir
    a lire le detail. La ligne d'en-tete a copier sort SOUS le panel, en
    Syntax : une CSP contient des crochets, que le balisage Rich prendrait
    pour des styles et avalerait silencieusement.
    """
    console.print(
        f"\n[bold]Recommandations[/bold] [grey58](redigees par {_ascii(report.model)})[/grey58]"
    )
    if report.summary:
        console.print(f"[grey70]{_ascii(report.summary)}[/grey70]")

    for conseil in report.advice:
        style = PRIORITY_STYLE.get(conseil.priority, "yellow")
        action = _ascii(conseil.action)
        corps = action
        if conseil.risk:
            corps = f"{_ascii(conseil.risk)}\n\n[bold]A faire :[/bold] {action}"
        console.print(
            Panel(
                corps,
                title=f"[bold]{_ascii(conseil.header)}[/bold]  [{style}]priorite {conseil.priority}[/{style}]",
                border_style=style,
                padding=(1, 2),
            )
        )
        if conseil.example:
            console.print(
                Syntax(_ascii(conseil.example), "http", theme="ansi_dark", word_wrap=True)
            )


def render_json(
    url: str,
    findings: list[Finding],
    score_value: int,
    grade_value: str,
    report: AiReport | None = None,
) -> str:
    """Meme rapport, en JSON, pour consommation machine.

    Les valeurs ne sont PAS tronquees ici : la troncature sert la lisibilite
    d'une table, elle n'a pas lieu d'etre dans une sortie destinee a un script.

    La cle `ai` vaut null quand le modele n'a pas ete sollicite ou n'a pas
    repondu : un script distingue ainsi "pas d'IA" de "rien a signaler".
    """
    return json.dumps(
        {
            "url": url,
            "score": score_value,
            "grade": grade_value,
            "findings": [asdict(finding) for finding in findings],
            "ai": asdict(report) if report is not None else None,
        },
        indent=2,
        ensure_ascii=False,
    )
