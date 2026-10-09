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
from .gate4_service import Service
from .models import (
    CAPABILITIES,
    ArtifactResponse,
    CapabilityRequest,
    CaseResponse,
    CreateCase,
    DeletionResponse,
)
from .storage import ApiError
from .web import register_web


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
        upload = scope["method"] == "POST" and scope["path"].endswith("/capture")
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
        # Reject oversized JSON before Pydantic parsing, including chunked requests.
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
    policy = policy or Policy()

    @asynccontextmanager
    async def lifespan(app):
        service = Service(data_root, policy)
        app.state.service = service
        try:
            yield
        finally:
            service.close()

    app = FastAPI(title="Wireclaw local API", version="0.4.0", lifespan=lifespan)
    app.add_middleware(Boundary, policy=policy)

    @app.exception_handler(ApiError)
    async def api_error(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=error.status)

    @app.exception_handler(AnalyzerError)
    async def analyzer_error(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=422)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # Framework errors contain user values and must not be echoed or logged.
        return JSONResponse({"error": {"code": "invalid_request"}}, status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, error):
        return JSONResponse({"error": {"code": "persistence_failure"}}, status_code=503)

    @app.exception_handler(Exception)
    async def internal_error(request, error):
        return JSONResponse({"error": {"code": "operation_failed"}}, status_code=500)

    def service():
        return app.state.service

    @app.get("/api/health")
    def health():
        return {"status": "ok", "gate": 4, "provider_mode": "none"}

    @app.get("/api/config/capabilities")
    def capabilities():
        return {
            "capabilities": list(CAPABILITIES),
            "provider_mode": "none",
            "provider_modes_supported_by_interface": [
                "none",
                "openai_compatible_cloud",
                "openai_compatible_local",
            ],
            "limits": {
                "max_cases": policy.max_cases,
                "max_runs": policy.max_runs,
                "max_capture_bytes": policy.analyzer.max_capture_bytes,
                "max_json_bytes": policy.max_json_bytes,
                "max_result_items": policy.max_result_items,
            },
        }

    @app.post("/api/cases", status_code=201, response_model=CaseResponse)
    def create(body: CreateCase):
        with service().admission():
            return service().create(body.symptom)

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
        if request.headers.get("content-type", "").split(";")[0] not in (
            "application/octet-stream",
            "application/vnd.tcpdump.pcap",
        ):
            raise ApiError("capture_content_type_required", 415)
        svc = service()
        with svc.admission():
            run_id, path = svc.begin_ingest(case_id)
            try:
                total = 0
                # Each chunk is written directly to a generated staging path.
                with path.open("xb") as stream:
                    async with asyncio.timeout(policy.upload_timeout_seconds):
                        async for chunk in request.stream():
                            total += len(chunk)
                            if total > policy.analyzer.max_capture_bytes:
                                raise ApiError("capture_size_limit", 413)
                            stream.write(chunk)
                return await run_in_threadpool(svc.ingest, case_id, run_id, path)
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
                svc.fail(case_id, run_id, code, fatal=True)
                svc.cleanup_ingest(case_id)
                raise ApiError(code, 413 if code == "capture_size_limit" else 422) from None
            finally:
                path.unlink(missing_ok=True)

    @app.post("/api/cases/{case_id}/investigate", response_model=CaseResponse)
    def investigate(case_id: str):
        with service().admission():
            return service().investigate(case_id)

    @app.post("/api/cases/{case_id}/capabilities")
    def capability(case_id: str, body: CapabilityRequest):
        with service().admission():
            return service().capability(case_id, body)

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

    register_web(app)
    return app
