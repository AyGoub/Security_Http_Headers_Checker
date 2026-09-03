"""Tests du module de redaction par le modele.

Aucun appel reseau reel : respx simule l'endpoint OpenAI-compatible. Ce qui
est verifie ici n'est pas la qualite du texte - elle depend du modele - mais
le CONTRAT : le module doit rester silencieux et degrader proprement quand
quoi que ce soit se passe mal, et ne jamais laisser passer une recommandation
que l'audit n'a pas demandee.
"""

import json

import httpx
import pytest
import respx

from shhc import ai, rules

ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


@pytest.fixture(autouse=True)
def _cle(monkeypatch):
    """Une cle bidon : les tests simulent le service, ils ne l'appellent pas."""
    monkeypatch.setenv("SHHC_AI_KEY", "cle-de-test")
    monkeypatch.delenv("SHHC_AI_BASE_URL", raising=False)
    monkeypatch.delenv("SHHC_AI_MODEL", raising=False)


@pytest.fixture
def findings():
    """Un site troue : HSTS desactive, CSP permissive, le reste absent."""
    return rules.analyze(
        {
            "strict-transport-security": "max-age=0",
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
        }
    )


def _reponse(charge: dict) -> httpx.Response:
    """Emballe une charge utile dans la forme d'une reponse chat/completions."""
    return httpx.Response(
        200,
        json={"choices": [{"message": {"content": json.dumps(charge, ensure_ascii=False)}}]},
    )


def test_sans_cle(monkeypatch, findings):
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    assert ai.is_configured() is False
    with pytest.raises(ai.AIUnavailable):
        ai.advise("https://exemple.test", findings)


def test_groq_api_key_accepte(monkeypatch):
    """Le nom propose par la console Groq marche sans renommage."""
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "cle-groq")

    assert ai.cle_api() == "cle-groq"


@respx.mock
def test_conseils_normalises(findings):
    route = respx.post(ENDPOINT).mock(
        return_value=_reponse(
            {
                "synthese": "Configuration incomplete.",
                "recommandations": [
                    {
                        "header": "content-security-policy",  # casse differente
                        "risque": "unsafe-inline annule la protection XSS.",
                        "action": "Passer aux nonces.",
                        "exemple": "Content-Security-Policy: default-src 'self'",
                        "priorite": "HAUTE",
                    },
                    {
                        "header": "Strict-Transport-Security",
                        "risque": "HSTS desactive.",
                        "action": "Remettre max-age=31536000.",
                        "exemple": None,
                        "priorite": "n'importe quoi",
                    },
                ],
            }
        )
    )

    rapport = ai.advise("https://exemple.test", findings)

    assert route.called
    assert rapport.summary == "Configuration incomplete."
    assert rapport.model == ai.DEFAUT_MODEL

    # L'ordre est celui des regles (HSTS avant CSP), pas celui du modele.
    assert [c.header for c in rapport.advice] == [
        "Strict-Transport-Security",
        "Content-Security-Policy",
    ]
    assert rapport.advice[0].priority == "moyenne"  # priorite inconnue -> defaut
    assert rapport.advice[0].example is None
    assert rapport.advice[1].priority == "haute"  # casse normalisee


@respx.mock
def test_en_tete_hallucine_ignore(findings):
    """Un en-tete que l'audit n'a pas produit ne doit jamais s'afficher."""
    respx.post(ENDPOINT).mock(
        return_value=_reponse(
            {
                "synthese": "",
                "recommandations": [
                    {"header": "X-Powered-By", "risque": "r", "action": "a", "priorite": "haute"},
                    {"header": "X-Frame-Options", "risque": "r", "action": "a", "priorite": "haute"},
                ],
            }
        )
    )

    rapport = ai.advise("https://exemple.test", findings)

    assert [c.header for c in rapport.advice] == ["X-Frame-Options"]


@respx.mock
def test_en_tete_conforme_ignore():
    """Recommander un en-tete deja `ok` contredirait la table affichee juste au-dessus."""
    findings = rules.analyze(
        {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        }
    )
    respx.post(ENDPOINT).mock(
        return_value=_reponse(
            {
                "synthese": "",
                "recommandations": [
                    {"header": "Strict-Transport-Security", "risque": "r", "action": "a"},
                    {"header": "Referrer-Policy", "risque": "r", "action": "a"},
                ],
            }
        )
    )

    rapport = ai.advise("https://exemple.test", findings)

    assert [c.header for c in rapport.advice] == ["Referrer-Policy"]


@respx.mock
def test_doublon_ignore(findings):
    respx.post(ENDPOINT).mock(
        return_value=_reponse(
            {
                "synthese": "",
                "recommandations": [
                    {"header": "X-Frame-Options", "risque": "premier", "action": "a"},
                    {"header": "X-Frame-Options", "risque": "second", "action": "b"},
                ],
            }
        )
    )

    rapport = ai.advise("https://exemple.test", findings)

    assert len(rapport.advice) == 1
    assert rapport.advice[0].risk == "premier"


@respx.mock
def test_action_vide_retombe_sur_le_statique(findings):
    respx.post(ENDPOINT).mock(
        return_value=_reponse(
            {
                "synthese": "",
                "recommandations": [{"header": "X-Frame-Options", "risque": "r", "action": ""}],
            }
        )
    )

    rapport = ai.advise("https://exemple.test", findings)

    statique = next(f for f in findings if f.header == "X-Frame-Options").recommendation
    assert rapport.advice[0].action == statique


@respx.mock
def test_texte_tronque(findings):
    respx.post(ENDPOINT).mock(
        return_value=_reponse(
            {
                "synthese": "s" * 2000,
                "recommandations": [
                    {"header": "X-Frame-Options", "risque": "r" * 2000, "action": "a"}
                ],
            }
        )
    )

    rapport = ai.advise("https://exemple.test", findings)

    assert len(rapport.summary) == ai.MAX_SUMMARY
    assert len(rapport.advice[0].risk) == ai.MAX_TEXTE


@respx.mock
def test_json_illisible(findings):
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200, json={"choices": [{"message": {"content": "Bien sur ! Voici mes conseils :"}}]}
        )
    )

    with pytest.raises(ai.AIUnavailable):
        ai.advise("https://exemple.test", findings)


@respx.mock
def test_forme_de_reponse_inattendue(findings):
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"erreur": "?"}))

    with pytest.raises(ai.AIUnavailable):
        ai.advise("https://exemple.test", findings)


@respx.mock
@pytest.mark.parametrize("code", [401, 429, 500])
def test_erreurs_http(findings, code):
    respx.post(ENDPOINT).mock(return_value=httpx.Response(code, json={"error": "non"}))

    with pytest.raises(ai.AIUnavailable):
        ai.advise("https://exemple.test", findings)


@respx.mock
def test_service_injoignable(findings):
    respx.post(ENDPOINT).mock(side_effect=httpx.ConnectError("dns"))

    with pytest.raises(ai.AIUnavailable):
        ai.advise("https://exemple.test", findings)


@respx.mock
def test_site_parfait_n_appelle_pas_le_modele():
    """Rien a corriger : pas de recommandation, donc pas d'aller-retour reseau."""
    findings = rules.analyze(
        {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        }
    )
    route = respx.post(ENDPOINT).mock(return_value=_reponse({"recommandations": []}))

    rapport = ai.advise("https://exemple.test", findings)

    assert not route.called
    assert rapport.advice == []


@respx.mock
def test_fournisseur_configurable(monkeypatch, findings):
    """Changer de fournisseur ne doit demander que des variables d'environnement."""
    monkeypatch.setenv("SHHC_AI_BASE_URL", "https://openrouter.test/api/v1/")
    monkeypatch.setenv("SHHC_AI_MODEL", "un-modele-gratuit:free")

    route = respx.post("https://openrouter.test/api/v1/chat/completions").mock(
        return_value=_reponse({"synthese": "", "recommandations": []})
    )

    rapport = ai.advise("https://exemple.test", findings)

    assert route.called
    envoye = json.loads(route.calls.last.request.content)
    assert envoye["model"] == "un-modele-gratuit:free"
    assert rapport.model == "un-modele-gratuit:free"


@respx.mock
def test_valeur_enorme_tronquee_avant_envoi():
    """Une CSP de plusieurs kilo-octets ne doit pas partir en entier."""
    findings = rules.analyze({"content-security-policy": "default-src *; " + "a" * 5000})
    route = respx.post(ENDPOINT).mock(return_value=_reponse({"recommandations": []}))

    ai.advise("https://exemple.test", findings)

    envoye = json.loads(route.calls.last.request.content)
    charge = json.loads(envoye["messages"][1]["content"])
    csp = next(h for h in charge["en_tetes"] if h["header"] == "Content-Security-Policy")
    assert len(csp["valeur"]) == ai.MAX_VALEUR_ENVOYEE


# --------------------------------------------------------------------------
# Lecture du fichier .env
#
# La conftest fait pointer FICHIER_ENV vers un fichier inexistant : chaque
# test ci-dessous le redirige vers son propre fichier temporaire.
# --------------------------------------------------------------------------


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Un .env jetable, avec le cache de chargement remis a zero."""

    def _ecrire(contenu: str):
        chemin = tmp_path / ".env"
        chemin.write_text(contenu, encoding="utf-8")
        monkeypatch.setattr(ai, "FICHIER_ENV", chemin)
        monkeypatch.setattr(ai, "_env_charge", False)
        return chemin

    return _ecrire


def test_cle_lue_dans_le_fichier(env_file, monkeypatch):
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    env_file("SHHC_AI_KEY=gsk_depuis_le_fichier\n")

    assert ai.cle_api() == "gsk_depuis_le_fichier"
    assert ai.is_configured() is True


def test_environnement_prioritaire_sur_le_fichier(env_file, monkeypatch):
    """En production, la variable du tableau de bord doit gagner."""
    monkeypatch.setenv("SHHC_AI_KEY", "gsk_de_l_environnement")
    env_file("SHHC_AI_KEY=gsk_du_fichier\n")

    assert ai.cle_api() == "gsk_de_l_environnement"


def test_fichier_absent_n_est_pas_une_erreur(monkeypatch, tmp_path):
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)  # pose par la fixture `_cle`
    monkeypatch.setattr(ai, "FICHIER_ENV", tmp_path / "rien-ici")
    monkeypatch.setattr(ai, "_env_charge", False)

    assert ai.cle_api() is None


def test_formats_de_ligne_toleres(env_file, monkeypatch):
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    env_file(
        "\n"
        "# un commentaire\n"
        "une ligne sans egal\n"
        '  export SHHC_AI_KEY = "gsk_entoure"  \n'
        "SHHC_AI_MODEL='un-modele'\n"
        "SHHC_AI_BASE_URL=https://ailleurs.test/v1/\n"
    )

    assert ai.cle_api() == "gsk_entoure"
    assert ai.modele() == "un-modele"
    assert ai.base_url() == "https://ailleurs.test/v1"  # slash final retire


def test_valeur_vide_ignoree(env_file, monkeypatch):
    """Le .env.example livre `SHHC_AI_KEY=` : il ne doit pas passer pour une cle."""
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    env_file("SHHC_AI_KEY=\n")

    assert ai.cle_api() is None


def test_fichier_lu_une_seule_fois(env_file, monkeypatch):
    """Le cache evite de relire le disque a chaque appel."""
    monkeypatch.delenv("SHHC_AI_KEY", raising=False)
    chemin = env_file("SHHC_AI_KEY=gsk_premier\n")

    assert ai.cle_api() == "gsk_premier"
    chemin.write_text("SHHC_AI_KEY=gsk_second\n", encoding="utf-8")
    assert ai.cle_api() == "gsk_premier"
