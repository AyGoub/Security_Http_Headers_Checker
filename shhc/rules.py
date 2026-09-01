"""Les six regles de notation.

Module PUR : pas de reseau, pas d'affichage, pas d'etat global. Une fonction
recoit un dict d'en-tetes en minuscules et renvoie un Finding. C'est ce qui
rend ce module testable sans mocker quoi que ce soit.

MVP 2 - a implementer.
"""

from collections.abc import Callable

from shhc.models import Finding

import re

Rule = Callable[[dict[str, str]], Finding]


def check_hsts(headers: dict[str, str]) -> Finding:
    """Strict-Transport-Security (poids 30).

    ok    : directive max-age >= HSTS_MIN_MAX_AGE (6 mois)
    weak  : en-tete present mais max-age absent, egal a 0, ou trop court
    missing : en-tete absent

    Le cas qui compte : `max-age=0` est une DESACTIVATION active de HSTS.
    L'en-tete est bien la, mais il annule la protection. Il doit ressortir en
    `weak`, jamais en `ok`. Parser la directive avec une regex du type
    `max-age\s*=\s*(\d+)` -- un simple `"max-age" in value` classerait
    `max-age=0` en `ok`, ce qui est exactement le bug a eviter.
    """
    value=headers.get("strict-transport-security")
    if value is None:
        return Finding(
            header="Strict-Transport-Security",
            status="missing",
            value=None,
            weight=30,
            points=0,
            reason="En-tete absent.",
            recommendation="Ajouter l'en-tete `Strict-Transport-Security`.",
        )
    match = re.search(r"max-age\s*=\s*(\d+)", value)
    if not match:
        return Finding(
            header="Strict-Transport-Security",
            status="weak",
            value=value,
            weight=30,
            points=15,
            reason="Directive `max-age` absente.",
            recommendation="Ajouter une directive `max-age` >= 15768000.",
        )
    max_age = int(match.group(1))
    if max_age == 0:
        return Finding(
            header="Strict-Transport-Security",
            status="weak",
            value=value,
            weight=30,
            points=15,
            reason="Directive `max-age` = 0 : HSTS desactive.",
            recommendation="Mettre `max-age` >= 15768000.",
        )
    if max_age < 15_768_000:
        return Finding(
            header="Strict-Transport-Security",
            status="weak",
            value=value,
            weight=30,
            points=15,
            reason=f"Directive `max-age` trop courte : {max_age}.",
            recommendation="Mettre `max-age` >= 15768000.",
        )
    return Finding(
        header="Strict-Transport-Security",
        status="ok",
        value=value,
        weight=30,
        points=30,
        reason=f"Directive `max-age` correcte : {max_age}.",
        recommendation=None,
    )
    


def check_csp(headers: dict[str, str]) -> Finding:
    """Content-Security-Policy (poids 30).

    ok    : politique presente et restrictive
    weak  : contient `unsafe-inline`, `unsafe-eval`, ou `default-src *`
    missing : en-tete absent ou vide
    """
    value=headers.get("content-security-policy")
    if value is None:
        return Finding(
            header="Content-Security-Policy",
            status="missing",
            value=None,
            weight=30,
            points=0,
            reason="En-tete absent.",
            recommendation="Ajouter l'en-tete `Content-Security-Policy`.",
        )
    if not value.strip():
        return Finding(
            header="Content-Security-Policy",
            status="missing",
            value=value,
            weight=30,
            points=0,
            reason="En-tete vide.",
            recommendation="Ajouter une politique restrictive.",
        )
    if any(x in value for x in ("unsafe-inline", "unsafe-eval", "default-src *")):
        return Finding(
            header="Content-Security-Policy",
            status="weak",
            value=value,
            weight=30,
            points=15,
            reason=f"Politique permissive : {value!r}.",
            recommendation="Retirer `unsafe-inline`, `unsafe-eval` et `default-src *`.",
        )
    return Finding(
        header="Content-Security-Policy",
        status="ok",
        value=value,
        weight=30,
        points=30,
        reason=f"Politique restrictive : {value!r}.",
        recommendation=None,
    )


def check_frame_options(headers: dict[str, str]) -> Finding:
    """X-Frame-Options (poids 15).

    ok    : DENY ou SAMEORIGIN (comparaison insensible a la casse)
    weak  : toute autre valeur, dont ALLOW-FROM qui est obsolete
    missing : en-tete absent
    """
    value=headers.get("x-frame-options")
    if value is None:
        return Finding(
            header="X-Frame-Options",
            status="missing",
            value=None,
            weight=15,
            points=0,
            reason="En-tete absent.",
            recommendation="Ajouter l'en-tete `X-Frame-Options`.",
        )
    if value.upper() not in ("DENY", "SAMEORIGIN"):
        return Finding(
            header="X-Frame-Options",
            status="weak",
            value=value,
            weight=15,
            points=7,
            reason=f"Valeur non sure : {value!r}.",
            recommendation="Mettre `X-Frame-Options: DENY` ou `SAMEORIGIN`.",
        )
    return Finding(
        header="X-Frame-Options",
        status="ok",
        value=value,
        weight=15,
        points=15,
        reason=f"Valeur correcte : {value!r}.",
        recommendation=None,
    )


def check_content_type_options(headers: dict[str, str]) -> Finding:
    """X-Content-Type-Options (poids 15).

    ok    : nosniff
    weak  : valeur non reconnue
    missing : en-tete absent
    """
    value=headers.get("x-content-type-options")
    if value is None:
        return Finding(
            header="X-Content-Type-Options",
            status="missing",
            value=None,
            weight=15,
            points=0,
            reason="En-tete absent.",
            recommendation="Ajouter l'en-tete `X-Content-Type-Options: nosniff`.",
        )
    if value!="nosniff":
        return Finding(
            header="X-Content-Type-Options",
            status="weak",
            value=value,
            weight=15,
            points=7,
            reason=f"Valeur non reconnue : {value!r}.",
            recommendation="Mettre `X-Content-Type-Options: nosniff`.",
        )
    return Finding(
        header="X-Content-Type-Options",
        status="ok",
        value=value,
        weight=15,
        points=15,
        reason="Valeur correcte.",
        recommendation=None,
    )



def check_referrer_policy(headers: dict[str, str]) -> Finding:
    """Referrer-Policy (poids 5).

    ok    : no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin
    weak  : unsafe-url ou toute autre valeur permissive
    missing : en-tete absent
    """
    value=headers.get("referrer-policy")
    if value is None:
        return Finding(
            header="Referrer-Policy",
            status="missing",
            value=None,
            weight=5,
            points=0,
            reason="En-tete absent.",
            recommendation="Ajouter l'en-tete `Referrer-Policy`.",
        )
    if value not in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"):
        return Finding(
            header="Referrer-Policy",
            status="weak",
            value=value,
            weight=5,
            points=2,
            reason=f"Valeur permissive : {value!r}.",
            recommendation="Mettre une valeur restrictive.",
        )
    return Finding(
        header="Referrer-Policy",
        status="ok",
        value=value,
        weight=5,
        points=5,
        reason=f"Valeur correcte : {value!r}.",
        recommendation=None,
    )


def check_permissions_policy(headers: dict[str, str]) -> Finding:
    """Permissions-Policy (poids 5).

    ok    : present et non vide
    weak  : present mais vide
    missing : en-tete absent
    """
    value=headers.get("permissions-policy")
    if value is None:
        return Finding(
            header="Permissions-Policy",
            status="missing",
            value=None,
            weight=5,
            points=0,
            reason="En-tete absent.",
            recommendation="Ajouter l'en-tete `Permissions-Policy`.",
        )
    if not value.strip():
        return Finding(
            header="Permissions-Policy",
            status="weak",
            value=value,
            weight=5,
            points=2,
            reason="En-tete vide.",
            recommendation="Ajouter une politique restrictive.",
        )
    return Finding(
        header="Permissions-Policy",
        status="ok",
        value=value,
        weight=5,
        points=5,
        reason=f"Valeur correcte : {value!r}.",
        recommendation=None,
    )


#: L'ordre de ce registre est l'ordre d'affichage dans la table finale :
#: du plus critique au moins critique.
RULES: list[Rule] = [
    check_hsts,
    check_csp,
    check_frame_options,
    check_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
]


def analyze(headers: dict[str, str]) -> list[Finding]:
    """Applique toutes les regles aux en-tetes recus."""
    return [rule(headers) for rule in RULES]
