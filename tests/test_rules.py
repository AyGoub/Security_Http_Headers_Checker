"""Tests du moteur de regles.

Les cas listes ici sont la specification executable du MVP 2. Retirer le
`pytestmark` ci-dessous des que les regles sont implementees.
"""

import pytest

from shhc import rules



class TestHSTS:
    def test_absent(self):
        assert rules.check_hsts({}).status == "missing"

    def test_valide(self):
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        assert rules.check_hsts(headers).status == "ok"

    def test_max_age_zero_est_weak_pas_ok(self):
        """Le cas central : l'en-tete est present mais desactive la protection."""
        headers = {"strict-transport-security": "max-age=0"}
        assert rules.check_hsts(headers).status == "weak"

    def test_max_age_trop_court(self):
        headers = {"strict-transport-security": "max-age=3600"}
        assert rules.check_hsts(headers).status == "weak"

    def test_sans_directive_max_age(self):
        headers = {"strict-transport-security": "includeSubDomains"}
        assert rules.check_hsts(headers).status == "weak"

    def test_valeur_vide(self):
        assert rules.check_hsts({"strict-transport-security": ""}).status == "weak"


class TestCSP:
    def test_absent(self):
        assert rules.check_csp({}).status == "missing"

    def test_restrictive(self):
        assert rules.check_csp({"content-security-policy": "default-src 'self'"}).status == "ok"

    @pytest.mark.parametrize(
        "value",
        [
            "default-src 'self'; script-src 'unsafe-inline'",
            "default-src 'self'; script-src 'unsafe-eval'",
            "default-src *",
        ],
    )
    def test_permissive(self, value):
        assert rules.check_csp({"content-security-policy": value}).status == "weak"


class TestFrameOptions:
    @pytest.mark.parametrize("value", ["DENY", "SAMEORIGIN", "sameorigin"])
    def test_valeurs_sures(self, value):
        assert rules.check_frame_options({"x-frame-options": value}).status == "ok"

    def test_allow_from_obsolete(self):
        headers = {"x-frame-options": "ALLOW-FROM https://example.com"}
        assert rules.check_frame_options(headers).status == "weak"


class TestContentTypeOptions:
    def test_nosniff(self):
        assert rules.check_content_type_options({"x-content-type-options": "nosniff"}).status == "ok"

    def test_valeur_inconnue(self):
        assert rules.check_content_type_options({"x-content-type-options": "sniff"}).status == "weak"


class TestReferrerPolicy:
    @pytest.mark.parametrize(
        "value", ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]
    )
    def test_politiques_strictes(self, value):
        assert rules.check_referrer_policy({"referrer-policy": value}).status == "ok"

    def test_unsafe_url(self):
        assert rules.check_referrer_policy({"referrer-policy": "unsafe-url"}).status == "weak"


class TestPermissionsPolicy:
    def test_present(self):
        assert rules.check_permissions_policy({"permissions-policy": "geolocation=()"}).status == "ok"

    def test_vide(self):
        assert rules.check_permissions_policy({"permissions-policy": ""}).status == "weak"


def test_analyze_renvoie_six_findings():
    assert len(rules.analyze({})) == 6
