"""Fixed compiled web assets on the existing loopback API origin; no file browser."""

import re
from pathlib import Path

from fastapi.responses import FileResponse

from .storage import ApiError

WEB_DIST = Path(__file__).resolve().parents[4] / "apps/web/dist"
ASSET = re.compile(r"[A-Za-z0-9_-]+\.(?:js|css)\Z")


def security_headers(bridge_port: int) -> dict[str, str]:
    if (
        isinstance(bridge_port, bool)
        or not isinstance(bridge_port, int)
        or not 1 <= bridge_port <= 65535
    ):
        raise ValueError("invalid_bridge_port")
    bridge_origin = f"http://127.0.0.1:{bridge_port}"
    return {
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            f"connect-src 'self' {bridge_origin}; img-src 'self'; base-uri 'none'; "
            "object-src 'none'; frame-ancestors 'none'; form-action 'self'"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def web_file(name: str | None = None, *, bridge_port: int = 8766):
    if name is not None and not ASSET.fullmatch(name):
        raise ApiError("web_asset_not_found", 404)
    path = WEB_DIST / "index.html" if name is None else WEB_DIST / "assets" / name
    # Never follow symlinked build files/directories, even inside a trusted checkout.
    if any(p.is_symlink() for p in (WEB_DIST, path.parent, path)):
        raise ApiError("web_asset_not_found", 404)
    if not path.is_file():
        raise ApiError(
            "web_build_required" if name is None else "web_asset_not_found",
            503 if name is None else 404,
        )
    media = (
        "text/html" if name is None else ("text/javascript" if name.endswith(".js") else "text/css")
    )
    return FileResponse(path, media_type=media, headers=security_headers(bridge_port))


def register_web(app, *, bridge_port: int):
    @app.get("/", include_in_schema=False)
    def index():
        return web_file(bridge_port=bridge_port)

    @app.get("/assets/{name}", include_in_schema=False)
    def asset(name: str):
        return web_file(name, bridge_port=bridge_port)
