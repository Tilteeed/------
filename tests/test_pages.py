import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from control_plane import pages


class StaticPageTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
