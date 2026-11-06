import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from control_plane import pages


class StaticPageTests(unittest.TestCase):
    def _page_response(self, control_ui_domain=None, request_headers=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "index.html").write_text("<!doctype html><title>Agent</title>", encoding="utf-8")
            app = FastAPI()
            app.include_router(pages.create_page_router(
                root, control_ui_domain=control_ui_domain))
            with TestClient(app) as client:
                return client.get("/agent", headers=request_headers or {})

    @staticmethod
    def _directives(response):
        header = response.headers["content-security-policy"]
        return {part.strip().split(None, 1)[0]: part.strip().split(None, 1)[1]
                for part in header.split(";")}

    def test_page_and_only_named_assets_are_served(self):
        self.assertTrue(hasattr(pages, "create_page_router"), "Page routes are missing")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "index.html").write_text("<!doctype html><title>Agent</title>", encoding="utf-8")
            (root / "app.js").write_text("export {};", encoding="utf-8")
            (root / "private.txt").write_text("not public", encoding="utf-8")
            app = FastAPI()
            app.include_router(pages.create_page_router(root))
            with TestClient(app) as client:
                response = client.get("/agent")
                self.assertEqual(response.status_code, 200)
                self.assertIn("text/html", response.headers["content-type"])
                self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
                self.assertEqual(client.get("/agent-assets/app.js").status_code, 200)
                self.assertEqual(client.get("/agent-assets/private.txt").status_code, 404)
                self.assertEqual(client.get("/agent-assets/%2e%2e/private.txt").status_code, 404)

    def test_form_action_uses_only_self_without_control_ui_domain(self):
        response = self._page_response()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._directives(response)["form-action"], "'self'")

    def test_form_action_allows_configured_agent_subdomains(self):
        response = self._page_response("agents.bezr.test")
        self.assertEqual(response.status_code, 200)
        directives = self._directives(response)
        self.assertEqual(
            directives["form-action"], "'self' https://*.agents.bezr.test")

    def test_invalid_configured_domain_adds_no_form_action_source(self):
        invalid_domains = (
            "agents.bezr.test; form-action https://evil.example",
            "*.agents.bezr.test", "https://agents.bezr.test",
            "agents.bezr.test:443", "agents.bezr.test.", "UPPER.example",
        )
        for domain in invalid_domains:
            with self.subTest(domain=domain):
                response = self._page_response(domain)
                self.assertEqual(self._directives(response)["form-action"], "'self'")

    def test_other_csp_directives_remain_restrictive(self):
        response = self._page_response("agents.bezr.test")
        directives = self._directives(response)
        self.assertEqual(directives, {
            "default-src": "'self'",
            "script-src": "'self'",
            "style-src": "'self'",
            "connect-src": "'self'",
            "img-src": "'self' data:",
            "base-uri": "'none'",
            "frame-ancestors": "'none'",
            "form-action": "'self' https://*.agents.bezr.test",
        })

    def test_request_host_and_origin_cannot_expand_form_action_policy(self):
        response = self._page_response("agents.bezr.test", {
            "host": "attacker.example",
            "origin": "https://evil.example",
        })
        self.assertEqual(response.status_code, 200)
        directives = self._directives(response)
        self.assertEqual(
            directives["form-action"], "'self' https://*.agents.bezr.test")
        self.assertNotIn("attacker.example", response.headers["content-security-policy"])
        self.assertNotIn("evil.example", response.headers["content-security-policy"])

    def test_agent_wildcard_is_not_added_to_asset_csp(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "index.html").write_text("<!doctype html>", encoding="utf-8")
            (root / "app.js").write_text("export {};", encoding="utf-8")
            app = FastAPI()
            app.include_router(pages.create_page_router(
                root, control_ui_domain="agents.bezr.test"))
            with TestClient(app) as client:
                page = client.get("/agent")
                self.assertEqual(
                    self._directives(page)["form-action"],
                    "'self' https://*.agents.bezr.test")
                self.assertEqual(page.headers["referrer-policy"], "strict-origin")
                asset = client.get("/agent-assets/app.js")
                self.assertEqual(self._directives(asset)["form-action"], "'self'")
                self.assertEqual(asset.headers["referrer-policy"], "same-origin")


if __name__ == "__main__":
    unittest.main()
