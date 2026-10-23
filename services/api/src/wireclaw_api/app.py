"""Loopback API: bounded requests, safe errors and typed analyzer operations."""

import asyncio
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from wireclaw_analyzer import AnalyzerError

from .config import Policy
from .gate7_service import Service
from .models import (
    CAPABILITIES,
    ArtifactResponse,
    BridgeGrantRequest,
    BridgeGrantResponse,
    CapabilitiesResponse,
    CapabilityRequest,
    CaptureResponse,
    CaseResponse,
    CreateCapture,
    CreateCase,
    DeletionResponse,
    EvidenceCaptureRequest,
    EvidenceCaptureResponse,
    FollowupRequest,
    FollowupResponse,
    HealthResponse,
    RecentCaseResponse,
    RenameCase,
    UpdateCapture,
)
from .reasoning.followup import answer_followup
from .storage import ApiError
from .web import register_web

FOLLOWUP_ERROR_CODES = {
    404: ("case_not_found", "report_not_found"),
    409: ("report_not_ready", "followup_unavailable"),
    413: ("request_size_limit",),
    422: ("invalid_request",),
    502: ("followup_response_invalid",),
    503: ("provider_unavailable",),
    504: ("provider_timeout",),
}


CASE_METADATA_ERROR_CODES = {
    400: ("invalid_content_length",),
    403: ("host_rejected", "origin_rejected"),
    408: ("request_timeout",),
    413: ("request_size_limit",),
    422: ("invalid_request",),
    500: ("operation_failed",),
    503: ("persistence_failure",),
}


def code_only_error_response(codes=()):
    """Describe the existing safe handler envelope without FastAPI's detail field."""
    code_schema = {"type": "string"}
    if codes:
        code_schema["enum"] = list(codes)
    return {
        "description": "Code-only error" + (": " + ", ".join(codes) if codes else ""),
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["code"],
                            "properties": {"code": code_schema},
                        }
                    },
                }
            }
        },
    }


class Boundary:
    def __init__(self, app, policy):
        self.app, self.policy = app, policy

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        allowed_hosts = {
            f"{host}{suffix}".encode()
            for host in ("localhost", "127.0.0.1", "[::1]")
            for suffix in ("", f":{self.policy.port}")
        }
        origins = {b"http://" + h for h in allowed_hosts}
        if headers.get(b"host", b"") not in allowed_hosts:
            return await JSONResponse({"error": {"code": "host_rejected"}}, 403)(
                scope, receive, send
            )
        if b"origin" in headers and headers[b"origin"] not in origins:
            return await JSONResponse({"error": {"code": "origin_rejected"}}, 403)(
                scope, receive, send
            )
        parts = scope["path"].strip("/").split("/")
        upload = (
            scope["method"] == "POST"
            and len(parts) == 4
            and parts[:2] == ["api", "cases"]
            and parts[3] == "capture"
        ) or (
            scope["method"] == "PUT"
            and len(parts) == 6
            and parts[:2] == ["api", "cases"]
            and parts[3] == "captures"
            and parts[5] == "data"
        )
        limit = self.policy.analyzer.max_capture_bytes if upload else self.policy.max_json_bytes
        length = headers.get(b"content-length")
        if length is not None:
            try:
                length = int(length)
                if length < 0:
                    raise ValueError
            except ValueError:
                return await JSONResponse({"error": {"code": "invalid_content_length"}}, 400)(
                    scope, receive, send
                )
            if length > limit:
                return await JSONResponse({"error": {"code": "request_size_limit"}}, 413)(
                    scope, receive, send
                )
        if upload:
            return await self.app(scope, receive, send)
        body = bytearray()
        try:
            async with asyncio.timeout(self.policy.upload_timeout_seconds):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > limit:
                        return await JSONResponse({"error": {"code": "request_size_limit"}}, 413)(
                            scope, receive, send
                        )
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse({"error": {"code": "request_timeout"}}, 408)(
                scope, receive, send
            )
        supplied = False

        async def replay():
            nonlocal supplied
            if not supplied:
                supplied = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def create_app(data_root: Path, policy: Policy | None = None):
    policy = policy or Policy.from_environment()

    @asynccontextmanager
    async def lifespan(app):
        service = Service(data_root, policy)
        app.state.service = service
        try:
            yield
        finally:
            service.close()

    app = FastAPI(title="Wireclaw local API", version="0.7.0", lifespan=lifespan)
    app.add_middleware(Boundary, policy=policy)

    @app.exception_handler(ApiError)
    async def api_error(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=error.status)

    @app.exception_handler(AnalyzerError)
    async def analyzer_error(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=422)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        return JSONResponse({"error": {"code": "invalid_request"}}, status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, error):
        return JSONResponse({"error": {"code": "persistence_failure"}}, status_code=503)

    @app.exception_handler(Exception)
    async def internal_error(request, error):
        return JSONResponse({"error": {"code": "operation_failed"}}, status_code=500)

    def service():
        return app.state.service

    @app.get("/api/health", response_model=HealthResponse)
    def health():
        return {
            "status": "ok",
            "gate": 7,
            "provider_mode": policy.provider_mode.value,
            "ai": service().ai_status(),
        }

    @app.get("/api/config/capabilities", response_model=CapabilitiesResponse)
    def capabilities():
        return {
            "capabilities": list(CAPABILITIES),
            "provider_mode": policy.provider_mode.value,
            "provider_modes_supported_by_interface": [
                "none",
                "openai_compatible_cloud",
                "openai_compatible_local",
                "embedded_local",
            ],
            "bridge": {"origin": f"http://127.0.0.1:{policy.bridge_port}"},
            "limits": {
                "max_cases": policy.max_cases,
                "max_runs": policy.max_runs,
                "max_capture_bytes": policy.analyzer.max_capture_bytes,
                "max_json_bytes": policy.max_json_bytes,
                "max_result_items": policy.max_result_items,
                "max_evidence_capture_bytes": policy.max_evidence_capture_bytes,
            },
            "ai": service().ai_status(),
        }

    @app.post("/api/cases", status_code=201, response_model=CaseResponse)
    def create(body: CreateCase):
        with service().admission():
            return service().create(body.symptom, body.capture_name)

    @app.get(
        "/api/cases",
        response_model=list[RecentCaseResponse],
        responses={
            **{
                status: code_only_error_response(codes)
                for status, codes in CASE_METADATA_ERROR_CODES.items()
            },
            "default": code_only_error_response(),
        },
    )
    def recent_cases(limit: int = Query(default=10, ge=1, le=10)):
        return service().recent(limit)

    @app.patch(
        "/api/cases/{case_id}",
        response_model=CaseResponse,
        responses={
            **{
                status: code_only_error_response(codes)
                for status, codes in {
                    **CASE_METADATA_ERROR_CODES,
                    404: ("case_not_found",),
                    422: ("invalid_request", "invalid_id"),
                    429: ("service_busy",),
                }.items()
            },
            "default": code_only_error_response(),
        },
    )
    def rename_case(case_id: str, body: RenameCase):
        with service().admission():
            return service().rename(case_id, body.display_name)

    @app.post(
        "/api/cases/{case_id}/captures",
        status_code=201,
        response_model=CaptureResponse,
        responses={"default": code_only_error_response(), 422: code_only_error_response()},
    )
    def create_capture(case_id: str, body: CreateCapture):
        with service().admission():
            return service().create_capture(case_id, **body.model_dump())

    @app.patch(
        "/api/cases/{case_id}/captures/{capture_id}",
        response_model=CaptureResponse,
        responses={"default": code_only_error_response(), 422: code_only_error_response()},
    )
    def update_capture(case_id: str, capture_id: str, body: UpdateCapture):
        with service().admission():
            return service().update_capture(
                case_id, capture_id, **body.model_dump(exclude_unset=True)
            )

    @app.delete(
        "/api/cases/{case_id}/captures/{capture_id}",
        response_model=DeletionResponse,
        responses={"default": code_only_error_response(), 422: code_only_error_response()},
    )
    def remove_capture(case_id: str, capture_id: str):
        with service().admission():
            return service().remove_capture(case_id, capture_id)

    @app.put(
        "/api/cases/{case_id}/captures/{capture_id}/data",
        response_model=CaptureResponse,
        responses={"default": code_only_error_response(), 422: code_only_error_response()},
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
                },
            }
        },
    )
    async def capture_data(case_id: str, capture_id: str, request: Request):
        return await upload_capture(case_id, request, capture_id)

    @app.post(
        "/api/cases/{case_id}/capture",
        response_model=CaseResponse,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
                },
            }
        },
    )
    async def capture(case_id: str, request: Request):
        return await upload_capture(case_id, request)

    async def upload_capture(case_id, request, capture_id=None):
        legacy = capture_id is None
        if request.headers.get("content-type", "").split(";")[0] not in (
            "application/octet-stream",
            "application/vnd.tcpdump.pcap",
        ):
            raise ApiError("capture_content_type_required", 415)
        svc = service()
        with svc.admission():
            if legacy:
                run_id, path = await run_in_threadpool(svc.begin_ingest, case_id)
                capture_id = await run_in_threadpool(svc.ingest_capture_id, case_id, run_id)
            else:
                run_id, path = await run_in_threadpool(
                    svc.begin_capture_ingest, case_id, capture_id
                )
            try:
                total = 0
                with path.open("xb") as stream:
                    async with asyncio.timeout(policy.upload_timeout_seconds):
                        async for chunk in request.stream():
                            total += len(chunk)
                            if total > policy.analyzer.max_capture_bytes:
                                raise ApiError("capture_size_limit", 413)
                            stream.write(chunk)
                if legacy:
                    return await run_in_threadpool(svc.ingest, case_id, run_id, path)
                return await run_in_threadpool(
                    svc.ingest_capture, case_id, capture_id, run_id, path
                )
            except BaseException as error:
                code = (
                    error.code
                    if isinstance(error, (ApiError, AnalyzerError))
                    else (
                        "upload_timeout"
                        if isinstance(error, TimeoutError)
                        else "capture_intake_failed"
                    )
                )
                await run_in_threadpool(svc.fail_capture_ingest, case_id, capture_id, run_id, code)
                if legacy:
                    await run_in_threadpool(svc.cleanup_ingest, case_id)
                else:
                    await run_in_threadpool(svc.cleanup_capture_ingest, case_id, capture_id)
                raise ApiError(code, 413 if code == "capture_size_limit" else 422) from None
            finally:
                path.unlink(missing_ok=True)

    @app.post("/api/cases/{case_id}/investigate", response_model=CaseResponse)
    def investigate(case_id: str):
        with service().admission():
            return service().investigate(case_id)

    @app.post(
        "/api/cases/{case_id}/followups",
        response_model=FollowupResponse,
        responses={
            **{
                status: code_only_error_response(codes)
                for status, codes in FOLLOWUP_ERROR_CODES.items()
            },
            # Other shared boundary and admission errors also use this envelope.
            "default": code_only_error_response(),
        },
    )
    def followup(case_id: str, body: FollowupRequest):
        with service().admission():
            return answer_followup(service(), case_id, body.question)

    @app.post("/api/cases/{case_id}/capabilities")
    def capability(case_id: str, body: CapabilityRequest):
        with service().admission():
            return service().capability(case_id, body)

    @app.post(
        "/api/cases/{case_id}/artifacts/evidence-capture",
        response_model=EvidenceCaptureResponse,
    )
    def evidence_capture(case_id: str, body: EvidenceCaptureRequest):
        with service().admission():
            return service().create_evidence_capture(
                case_id, body.finding_id, capture_id=body.capture_id
            )

    @app.post("/api/cases/{case_id}/bridge-grants", response_model=BridgeGrantResponse)
    def bridge_grant(case_id: str, body: BridgeGrantRequest):
        with service().admission():
            return service().create_bridge_grant(case_id, body.artifact_id, body.finding_id)

    @app.get("/api/cases/{case_id}", response_model=CaseResponse)
    def get_case(case_id: str):
        return service().get(case_id)

    @app.get("/api/cases/{case_id}/evidence")
    def evidence(
        case_id: str, offset: int = Query(0, ge=0, le=2**31 - 1), limit: int = Query(100, ge=1)
    ):
        if limit > policy.max_result_items:
            raise ApiError("result_count_limit", 413)
        return {"evidence": service().evidence(case_id, offset=offset, limit=limit)}

    @app.get("/api/cases/{case_id}/evidence/{evidence_id}")
    def evidence_item(case_id: str, evidence_id: str):
        if len(evidence_id) > 256:
            raise ApiError("invalid_evidence_id", 422)
        return service().evidence(case_id, evidence_id=evidence_id)

    @app.get("/api/cases/{case_id}/findings")
    def findings(
        case_id: str, offset: int = Query(0, ge=0, le=2**31 - 1), limit: int = Query(100, ge=1)
    ):
        if limit > policy.max_result_items:
            raise ApiError("result_count_limit", 413)
        records = service().findings(case_id)
        return {"findings": records[offset : offset + limit]}

    @app.get("/api/cases/{case_id}/report")
    def report(case_id: str):
        return service().report(case_id)

    @app.get("/api/cases/{case_id}/artifacts/{artifact_id}", response_model=ArtifactResponse)
    def artifact_metadata(case_id: str, artifact_id: str):
        row, _ = service().artifact(case_id, artifact_id)
        return {k: row[k] for k in ("id", "kind", "sha256", "bytes", "parent_sha")}

    @app.delete("/api/cases/{case_id}", response_model=DeletionResponse)
    def delete(case_id: str):
        with service().admission():
            return service().delete(case_id)

    register_web(app, bridge_port=policy.bridge_port)
    return app
