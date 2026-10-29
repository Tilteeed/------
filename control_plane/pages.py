"""Static management page; authentication is required only for data APIs."""

from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse


_PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
}


def create_page_router(asset_directory: str | Path):
    root = Path(asset_directory)
    router = APIRouter(include_in_schema=False)

    @router.get("/agent")
    def page():
        return FileResponse(root / "index.html", media_type="text/html", headers=_PAGE_HEADERS)

    @router.get("/agent/")
    def canonical_page():
        return RedirectResponse("/agent", status_code=307)

    @router.get("/agent-assets/{filename}")
    def asset(filename: str):
        allowed = {"app.js": "application/javascript", "ui-state.mjs": "application/javascript", "styles.css": "text/css"}
        if filename not in allowed or not (root / filename).is_file():
            raise HTTPException(404, "Asset not found")
        return FileResponse(root / filename, media_type=allowed[filename], headers=_PAGE_HEADERS)

    return router
