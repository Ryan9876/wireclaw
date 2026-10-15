"""Minimal OpenAI-compatible chat-completions client with bounded I/O."""

import asyncio
import json

import httpx

from ..config import ProviderMode
from ..reasoning.contracts import ACTION_ADAPTER
from .models import ProviderFailure, ProviderResult, ReasoningRequest


class OpenAICompatibleProvider:
    def __init__(
        self,
        *,
        mode: ProviderMode,
        base_url: str,
        model: str,
        timeout_seconds: float,
        api_key: str | None,
    ):
        self.mode = mode.value
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key

    def propose(self, request: ReasoningRequest) -> ProviderResult:
        request_body = {
                "model": request.model,
                "messages": [
                    {"role": "system", "content": request.system_instruction},
                    {"role": "user", "content": request.context_json},
                ],
                "temperature": 0,
            }
        if self.mode == ProviderMode.EMBEDDED.value:
            request_body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "wireclaw_reasoning_action",
                    "strict": True,
                    "schema": ACTION_ADAPTER.json_schema(),
                },
            }
        body = json.dumps(
            request_body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        if len(body) > request.max_request_bytes:
            return ProviderResult(failure_code="provider_request_too_large")
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        try:
            output = asyncio.run(self._read_response(body, headers, request.max_response_bytes))
            try:
                decoded = json.loads(output)
                content = decoded["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise ProviderFailure("provider_invalid_response") from None
            if not isinstance(content, str):
                raise ProviderFailure("provider_invalid_response")
            if len(content.encode()) > request.max_response_bytes:
                raise ProviderFailure("provider_response_too_large")
            return ProviderResult(content=content)
        except ProviderFailure as error:
            return ProviderResult(failure_code=error.code)
        except (httpx.TimeoutException, TimeoutError):
            return ProviderResult(failure_code="provider_timeout")
        except httpx.HTTPError:
            return ProviderResult(failure_code="provider_unavailable")
        except Exception:
            # Never return or log provider exceptions; they may contain headers or bodies.
            return ProviderResult(failure_code="provider_protocol_error")

    async def _read_response(self, body, headers, maximum):
        # The outer deadline bounds the whole operation, including a slow trickle response.
        async with asyncio.timeout(self.timeout_seconds):
            async with (
                httpx.AsyncClient(
                    timeout=self.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    content=body,
                ) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise ProviderFailure("provider_protocol_error")
                if response.status_code in (401, 403):
                    raise ProviderFailure("provider_auth_failed")
                if response.status_code >= 500:
                    raise ProviderFailure("provider_unavailable")
                if response.status_code >= 400:
                    raise ProviderFailure("provider_protocol_error")
                output = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(output) + len(chunk) > maximum:
                        raise ProviderFailure("provider_response_too_large")
                    output.extend(chunk)
                return output
