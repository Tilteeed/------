"""Open WebUI bootstrap glue. Production identity comes only from upstream."""
import os
from pathlib import Path
from fastapi import APIRouter

from open_webui.env import DATA_DIR
from open_webui.utils.auth import get_verified_user

from .api import create_router
from .access_proxy import create_handoff_router
from .pages import create_page_router
from .store import DraftStore
from .runtime import configured_client

router = APIRouter()
platform_store = DraftStore(Path(DATA_DIR) / "agent-platform.sqlite3")
public_origin = os.environ.get("AGENT_PLATFORM_PUBLIC_ORIGIN") or None
control_ui_domain = os.environ.get("AGENT_CONTROL_UI_DOMAIN") or None
router.include_router(create_router(
    get_verified_user,
    platform_store,
    public_origin=public_origin,
    runtime=configured_client(),
    control_ui_domain=control_ui_domain,
))
router.include_router(create_handoff_router(
    platform_store, public_origin=public_origin, control_ui_domain=control_ui_domain,
))
router.include_router(create_page_router(Path(__file__).parent / "static"))
