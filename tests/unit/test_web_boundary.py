"""Gate 5 static UI serving preserves loopback and fixed-path boundaries."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from wireclaw_api import create_app


@pytest.fixture
def web_client(tmp_path):
    dist = tmp_path / "web"
    dist.mkdir()
    (dist / "assets").mkdir()
    (dist / "index.html").write_text("<!doctype html><h1>Wireclaw</h1>")
    (dist / "assets/index-abc123.js").write_text("console.log('safe build')")
    (tmp_path / "secret.txt").write_text("PRIVATE")
    with (
        patch("wireclaw_api.web.WEB_DIST", dist),
        TestClient(create_app(tmp_path / "data"), base_url="http://127.0.0.1:8765") as client,
    ):
        yield client, dist


def test_web_same_origin_security_headers_and_unchanged_api(web_client):
    client, _ = web_client
    response = client.get("/")
    assert response.status_code == 200
    assert "Wireclaw" in response.text
    csp = response.headers["content-security-policy"]
    assert "connect-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    asset = client.get("/assets/index-abc123.js")
    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"]
    assert client.get("/", headers={"host": "evil.invalid"}).status_code == 403
    assert client.get("/", headers={"origin": "http://evil.invalid"}).status_code == 403
    assert client.get("/api/health").json()["provider_mode"] == "none"
    assert "/" not in client.app.openapi()["paths"]


@pytest.mark.parametrize(
    "url",
    [
        "/assets/secret.txt",
        "/assets/..%2F..%2Fsecret.txt",
        "/assets/..%5C..%5Csecret.txt",
        "/assets/index-abc123.js.map",
        "/data/cases/secret.txt",
        "/src/App.tsx",
    ],
)
def test_web_has_no_source_artifact_or_arbitrary_file_access(web_client, url):
    client, _ = web_client
    response = client.get(url)
    assert response.status_code == 404
    assert "PRIVATE" not in response.text


def test_web_rejects_symlinked_assets_and_index(web_client, tmp_path):
    client, dist = web_client
    (dist / "assets/escape.js").symlink_to(tmp_path / "secret.txt")
    assert client.get("/assets/escape.js").status_code == 404
    (dist / "index.html").unlink()
    (dist / "index.html").symlink_to(tmp_path / "secret.txt")
    assert client.get("/").status_code == 404


def test_missing_web_build_is_explicit_without_breaking_api(tmp_path):
    with (
        patch("wireclaw_api.web.WEB_DIST", tmp_path / "missing"),
        TestClient(create_app(tmp_path / "data"), base_url="http://127.0.0.1:8765") as client,
    ):
        assert client.get("/").status_code == 503
        assert client.get("/").json()["error"]["code"] == "web_build_required"
        assert client.get("/api/health").status_code == 200
