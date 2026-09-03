"""Structures de donnees partagees par toutes les couches.

Ce module ne depend de rien : ni reseau, ni affichage. C'est le contrat entre
`rules` (qui produit des Finding), `scoring` (qui les note) et `render`
(qui les affiche).
"""

from dataclasses import dataclass
from typing import Literal

Status = Literal["ok", "weak", "missing"]

#: Poids de chaque en-tete. La somme fait exactement 100, donc le score final
#: est la simple addition des points obtenus.
WEIGHTS: dict[str, int] = {
    "strict-transport-security": 30,
    "content-security-policy": 30,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 5,
    "permissions-policy": 5,
}

#: Fraction du poids accordee selon le statut.
STATUS_FACTOR: dict[str, float] = {
    "ok": 1.0,
    "weak": 0.5,
    "missing": 0.0,
}

#: Seuils de notation, du meilleur au pire. Le premier seuil atteint gagne.
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]

#: Duree minimale acceptee pour HSTS : 6 mois, en secondes.
HSTS_MIN_MAX_AGE = 15_768_000


@dataclass
class Finding:
    """Le resultat de l'analyse d'un en-tete.

    Attributes:
        header: nom canonique de l'en-tete, tel qu'affiche a l'utilisateur.
        status: "ok", "weak" ou "missing".
        value: la valeur brute recue, ou None si l'en-tete est absent.
        weight: le poids de l'en-tete dans la note (30, 15 ou 5).
        points: les points reellement obtenus.
        reason: une ligne expliquant pourquoi ce statut.
        recommendation: quoi faire pour corriger. None si status == "ok".
    """

    header: str
    status: Status
    value: str | None
    weight: int
    points: int
    reason: str
    recommendation: str | None = None


@dataclass
class Advice:
    """Une recommandation redigee par le modele pour UN en-tete.

    `Finding.recommendation` reste la phrase statique de secours : elle est
    toujours produite, meme sans reseau et sans cle. `Advice` est la version
    enrichie, qui tient compte de la VALEUR reellement observee.

    Attributes:
        header: nom canonique de l'en-tete, tel qu'il apparait dans le Finding.
        risk: le risque concret, en une phrase, pour ce site precis.
        action: ce qu'il faut faire, formule a l'imperatif.
        example: la ligne d'en-tete a poser, prete a copier. None si sans objet.
        priority: "haute", "moyenne" ou "basse".
    """

    header: str
    risk: str
    action: str
    example: str | None = None
    priority: str = "moyenne"


@dataclass
class AiReport:
    """Le retour complet du modele : une synthese et des conseils cibles.

    Attributes:
        summary: deux ou trois phrases sur la posture globale du site.
        advice: un conseil par en-tete non conforme, dans l'ordre des regles.
        model: l'identifiant du modele qui a redige le rapport, pour tracabilite.
    """

    summary: str
    advice: list[Advice]
    model: str
