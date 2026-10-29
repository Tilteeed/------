"""Open WebUI bootstrap glue. Production identity comes only from upstream."""
import os
from pathlib import Path
from fastapi import APIRouter

from open_webui.env import DATA_DIR
from open_webui.utils.auth import get_verified_user

from .api import create_router
from .pages import create_page_router
from .store import DraftStore

router = APIRouter()
router.include_router(create_router(
    get_verified_user,
    DraftStore(Path(DATA_DIR) / "agent-platform.sqlite3"),
    public_origin=os.environ.get("AGENT_PLATFORM_PUBLIC_ORIGIN") or None,
))
router.include_router(create_page_router(Path(__file__).parent / "static"))
