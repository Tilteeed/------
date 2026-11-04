"""Open WebUI bootstrap glue. Production identity comes only from upstream."""
import os
from pathlib import Path
from fastapi import APIRouter

from open_webui.env import DATA_DIR
from open_webui.utils.auth import get_verified_user

from .api import create_router
from .access_proxy import create_control_ui_access_proxy
from .pages import create_page_router
from .store import DraftStore
from .runtime import configured_client

router = APIRouter()
platform_store = DraftStore(Path(DATA_DIR) / "agent-platform.sqlite3")
public_origin = os.environ.get("AGENT_PLATFORM_PUBLIC_ORIGIN") or None
control_ui_domain = os.environ.get("AGENT_CONTROL_UI_DOMAIN") or None
runtime_client = configured_client()
proxy_target_resolver = getattr(runtime_client, 'control_ui_target', None)
control_ui_proxy_app = create_control_ui_access_proxy(
    platform_store, runtime_client, public_origin=public_origin,
    control_ui_domain=control_ui_domain, target_resolver=proxy_target_resolver,
    proxy_ready=callable(proxy_target_resolver),
)
router.include_router(create_router(
    get_verified_user,
    platform_store,
    public_origin=public_origin,
    runtime=runtime_client,
    control_ui_domain=control_ui_domain,
    control_ui_proxy_ready=control_ui_proxy_app.state.proxy_ready,
    control_ui_pairing_service=control_ui_proxy_app.state.pairing_service,
))
router.include_router(create_page_router(Path(__file__).parent / "static"))
