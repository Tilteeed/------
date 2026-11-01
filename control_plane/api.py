"""FastAPI routes hosted by Open WebUI, not a replacement authentication system."""

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from urllib.parse import quote

from .policy import require_owner, validate_agent_input
from .store import RevisionConflict
from .runtime import RuntimeRejected, RuntimeUnavailable


def _workspace_path(value, *, allow_empty=False):
    if type(value) is not str or chr(0) in value or chr(92) in value:
        raise HTTPException(400, "Invalid workspace path")
    try:
        if len(value.encode("utf-8")) > 1024:
            raise HTTPException(400, "Invalid workspace path")
    except UnicodeEncodeError:
        raise HTTPException(400, "Invalid workspace path") from None
    if not value and allow_empty:
        return value
    parts = value.split("/")
    if (value.startswith("/") or len(parts) > 16
            or any(part in ("", ".", "..") or part.startswith(".")
                   or len(part.encode("utf-8")) > 255
                   or any(ord(char) < 32 or ord(char) == 127 for char in part)
                   for part in parts)):
        raise HTTPException(400, "Invalid workspace path")
    return value


def create_router(verified_user, store, *, public_origin: str | None = None, runtime=None):
    """Use the upstream verified-user dependency; never accept user-id headers."""
    router = APIRouter(prefix="/api/v1/agent-platform", tags=["agent-platform"])

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON fields are forbidden")
            result[key] = value
        return result

    async def mutation_body(request: Request):
        origin = request.headers.get("origin")
        expected = public_origin or str(request.base_url).rstrip("/")
        if (origin is not None and origin != expected) or request.headers.get("sec-fetch-site") == "cross-site":
            raise HTTPException(403, "Cross-origin mutations are forbidden")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise HTTPException(415, "application/json required")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > 65536:
                raise HTTPException(413, "Request body exceeds 64 KiB")
            data.extend(chunk)
        try:
            return json.loads(data, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(400, "Invalid JSON object") from None

    def explicit_bearer(request: Request):
        values = request.headers.getlist("authorization")
        if len(values) != 1:
            raise HTTPException(401, "Explicit session Bearer token required")
        parts = values[0].split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or parts[1].startswith("sk-"):
            raise HTTPException(401, "Explicit session Bearer token required")

    def actor(request: Request, gate=Depends(explicit_bearer), user=Depends(verified_user)):
        if (
            user.role not in {"user", "admin"}
            or getattr(request.state, "auth_type", None) != "jwt"
            or getattr(request.state, "claims", {}).get("typ", "session") != "session"
        ):
            raise HTTPException(403, "Active human session required")
        try:
            require_owner(user.id, user.id)
        except PermissionError:
            raise HTTPException(403, "Invalid user identity") from None
        return user

    @router.get("/me")
    def get_me(response: Response, user=Depends(actor)):
        response.headers["Cache-Control"] = "no-store"
        result = {
            "user": {"id": user.id, "name": user.name, "role": user.role},
            "draft": store.get(user.id),
            "capabilities": {"provisioning": False, "chat": False, "telegram": False, "metrics": False},
            "runtime": {"state": "not_connected", "gateway": "not_connected", "model": "not_connected", "telegram": "not_connected"},
        }
        if runtime is not None:
            try:
                result.update(runtime.get(user.id))
            except (RuntimeUnavailable, RuntimeRejected):
                result["runtime"]["state"] = "unavailable"
        return result

    @router.put("/me/settings")
    async def put_settings(request: Request, response: Response, user=Depends(actor)):
        try:
            payload = await mutation_body(request)
            if not isinstance(payload, dict) or set(payload) != {"settings", "revision"}:
                raise ValueError("Only settings and revision are accepted")
            settings = validate_agent_input(payload["settings"])
            result = await run_in_threadpool(store.save, user.id, settings, expected_revision=payload["revision"])
        except RevisionConflict as error:
            raise HTTPException(409, {"code": "revision_conflict", "message": str(error)}) from None
        except (ValueError, TypeError) as error:
            raise HTTPException(400, {"code": "invalid_settings", "message": str(error)}) from None
        response.headers["Cache-Control"] = "no-store"
        return {"draft": result}

    @router.get("/me/events")
    def get_events(response: Response, user=Depends(actor)):
        response.headers["Cache-Control"] = "no-store"
        return {"events": store.events(user.id)}

    def require_runtime():
        if runtime is None:
            raise HTTPException(503, {"code": "runtime_not_connected", "message": "Supervisor недоступен."})
        return runtime

    def retained_target(instance_id):
        if type(instance_id) is not str or re.fullmatch(r"[0-9a-f]{32}", instance_id) is None:
            raise HTTPException(400, "Valid retained instance ID required")
        require_runtime()
        return instance_id

    @router.get("/me/retained/{instance_id}/files")
    async def get_retained_files(instance_id: str, request: Request, response: Response,
                                 user=Depends(actor)):
        client = require_runtime()
        instance_id = retained_target(instance_id)
        values = request.query_params.getlist("directory")
        offset_values = request.query_params.getlist("offset")
        if len(values) > 1 or len(offset_values) > 1:
            raise HTTPException(400, "Only one directory and offset are accepted")
        directory = _workspace_path(values[0] if values else "", allow_empty=True)
        raw_offset = offset_values[0] if offset_values else "0"
        if not raw_offset.isascii() or not raw_offset.isdecimal() or len(raw_offset) > 5:
            raise HTTPException(400, "Invalid workspace offset")
        offset = int(raw_offset)
        if offset > 10000:
            raise HTTPException(400, "Invalid workspace offset")
        try:
            result = await run_in_threadpool(client.workspace_list, user.id, instance_id, directory, offset)
        except RuntimeUnavailable:
            raise HTTPException(503, {"code": "supervisor_unavailable", "message": "Supervisor недоступен."}) from None
        except RuntimeRejected as error:
            raise HTTPException(error.status, {"code": error.code, "message": error.message}) from None
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.get("/me/retained/{instance_id}/files/preview")
    async def preview_retained_file(instance_id: str, request: Request, response: Response,
                                    user=Depends(actor)):
        client = require_runtime()
        instance_id = retained_target(instance_id)
        values = request.query_params.getlist("path")
        if len(values) != 1:
            raise HTTPException(400, "One file path is required")
        path = _workspace_path(values[0])
        try:
            result = await run_in_threadpool(client.workspace_preview, user.id, instance_id, path)
        except RuntimeUnavailable:
            raise HTTPException(503, {"code": "supervisor_unavailable", "message": "Supervisor недоступен."}) from None
        except RuntimeRejected as error:
            raise HTTPException(error.status, {"code": error.code, "message": error.message}) from None
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.get("/me/retained/{instance_id}/files/download")
    async def download_retained_file(instance_id: str, request: Request,
                                     user=Depends(actor)):
        client = require_runtime()
        instance_id = retained_target(instance_id)
        values = request.query_params.getlist("path")
        if len(values) != 1:
            raise HTTPException(400, "One file path is required")
        path = _workspace_path(values[0])
        try:
            content = await run_in_threadpool(client.workspace_download, user.id, instance_id, path)
        except RuntimeUnavailable:
            raise HTTPException(503, {"code": "supervisor_unavailable", "message": "Supervisor недоступен."}) from None
        except RuntimeRejected as error:
            raise HTTPException(error.status, {"code": error.code, "message": error.message}) from None
        filename = quote(path.rsplit("/", 1)[-1], safe="")
        return Response(content=content, media_type="application/octet-stream", headers={
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f"attachment; filename=download; filename*=UTF-8''{filename}",
        })

    @router.post("/me/actions")
    async def lifecycle_action(request: Request, response: Response, user=Depends(actor)):
        response.headers["Cache-Control"] = "no-store"
        payload = await mutation_body(request)
        allowed_actions = {'create', 'start', 'stop', 'restart', 'remove', 'purge', 'restore'}
        if runtime is not None:
            base_keys = {'action', 'idempotency_key', 'settings_revision'}
            action = payload.get('action') if type(payload) is dict else None
            expected_keys = base_keys | {'instance_id'} if type(action) is str and action in {'purge', 'restore'} else base_keys
            if (type(payload) is not dict
                    or set(payload) != expected_keys
                    or type(payload['action']) is not str or payload['action'] not in allowed_actions
                    or type(payload['idempotency_key']) is not str
                    or not 1 <= len(payload['idempotency_key']) <= 128
                    or any(not (c.isascii() and (c.isalnum() or c in '_-')) for c in payload['idempotency_key'])
                    or type(payload['settings_revision']) is not int
                    or not 1 <= payload['settings_revision'] <= 2**53 - 1
                    or (action in {'purge', 'restore'} and (type(payload['instance_id']) is not str
                        or re.fullmatch(r'[0-9a-f]{32}', payload['instance_id']) is None))):
                raise HTTPException(400, "Supported action, idempotency_key and saved settings_revision required")
            try:
                try:
                    return await run_in_threadpool(runtime.replay, user.id, payload)
                except RuntimeRejected as error:
                    if error.status != 404 or error.code != 'operation_not_found':
                        raise
                draft = await run_in_threadpool(store.get, user.id)
                if draft is None or draft["revision"] != payload["settings_revision"]:
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Перечитайте сохранённые настройки перед операцией."})
                result = await run_in_threadpool(runtime.action, user.id, payload, draft)
            except RuntimeUnavailable:
                raise HTTPException(503, {"code": "supervisor_unavailable", "message": "Связь с supervisor недоступна. Результат операции неизвестен: обновите состояние перед повтором."}) from None
            except RuntimeRejected as error:
                raise HTTPException(error.status, {"code": error.code, "message": error.message}) from None
            return result
        if (
            not isinstance(payload, dict)
            or set(payload) != {"action"}
            or not isinstance(payload["action"], str)
            or payload["action"] not in allowed_actions
        ):
            raise HTTPException(400, "Only a supported action is accepted")
        raise HTTPException(
            503,
            {"code": "runtime_not_connected", "message": "Сервис развёртывания ещё не подключён. Контейнер не создан и не изменён."},
            headers={"Cache-Control": "no-store"},
        )

    return router
