"""Static management page; authentication is required only for data APIs."""

import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse


_PAGE_CSP_PREFIX = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
    "frame-ancestors 'none'; "
)
_PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}


_CONTROL_UI_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
_CONTROL_UI_DOMAIN = re.compile(_CONTROL_UI_LABEL + r'(?:\.' + _CONTROL_UI_LABEL + r')*')


def _page_headers(control_ui_domain=None):
    form_action = "'self'"
    if (type(control_ui_domain) is str and len(control_ui_domain) <= 253
            and _CONTROL_UI_DOMAIN.fullmatch(control_ui_domain) is not None):
        form_action += " https://*." + control_ui_domain
    return {
        **_PAGE_HEADERS,
        'Content-Security-Policy': _PAGE_CSP_PREFIX + 'form-action ' + form_action,
    }


def create_page_router(asset_directory: str | Path, *, control_ui_domain: str | None = None):
    root = Path(asset_directory)
    router = APIRouter(include_in_schema=False)
    page_headers = {
        **_page_headers(control_ui_domain),
        'Referrer-Policy': 'strict-origin',
    }
    asset_headers = _page_headers()

    @router.get("/agent")
    def page():
        return FileResponse(root / "index.html", media_type="text/html", headers=page_headers)

    @router.get("/agent/")
    def canonical_page():
        return RedirectResponse("/agent", status_code=307)

    @router.get("/agent-assets/{filename}")
    def asset(filename: str):
        allowed = {"app.js": "application/javascript", "ui-state.mjs": "application/javascript", "styles.css": "text/css"}
        if filename not in allowed or not (root / filename).is_file():
            raise HTTPException(404, "Asset not found")
        return FileResponse(root / filename, media_type=allowed[filename], headers=asset_headers)

    return router
