"""Point d'entree CLI : orchestre fetch -> rules -> scoring -> render.

Cette couche ne contient AUCUNE logique metier. Elle enchaine les modules,
traduit les erreurs en messages lisibles et choisit le code de sortie.
"""

import typer
from rich.console import Console

from shhc import __version__, fetch, render, rules, scoring

app = typer.Typer(add_completion=False, help="Note les en-tetes de securite d'une URL.")
err_console = Console(stderr=True)


def _version(value: bool) -> None:
    """Option eager : affiche la version et court-circuite le reste."""
    if value:
        print(f"shhc {__version__}")
        raise typer.Exit()


@app.command()
def check(
    url: str = typer.Argument(..., help="L'URL a analyser. Le https:// est optionnel."),
    as_json: bool = typer.Option(False, "--json", help="Sortie machine, sans couleurs."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Affiche seulement le score et le grade."),
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Affiche la version et quitte."
    ),
) -> None:
    """Analyse les en-tetes de securite de URL et renvoie une note A-F."""
    try:
        target = fetch.normalize_url(url)
    except ValueError as exc:
        err_console.print(f"[red]Erreur :[/red] {exc}")
        raise typer.Exit(code=2)

    try:
        final_url, headers = fetch.fetch(target)
    except fetch.FetchError as exc:
        err_console.print(f"[red]Impossible d'atteindre {target} :[/red] {exc}")
        raise typer.Exit(code=2)

    findings = rules.analyze(headers)
    score_value = scoring.score(findings)
    grade_value = scoring.grade(score_value)

    if as_json:
        print(render.render_json(final_url, findings, score_value, grade_value))
    elif quiet:
        print(f"{score_value}/100 {grade_value}")
    else:
        render.render_report(final_url, findings, score_value, grade_value)

    raise typer.Exit(code=scoring.exit_code(grade_value))


if __name__ == "__main__":
    app()
