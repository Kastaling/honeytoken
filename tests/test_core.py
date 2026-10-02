import base64
import json
from pathlib import Path

import admin_app
import config_store
import store
import trap_app
from proxy_trust import resolve_client_ip


def _basic_auth() -> dict[str, str]:
    token = base64.b64encode(b"test-admin:test-password").decode()
    return {"Authorization": f"Basic {token}"}


def test_tracked_link_create_and_update():
    link = store.create_tracked_link(
        host="example.com",
        settings={"mode": "error", "status_code": 404},
        label="initial",
    )
    assert link["path"].startswith("/l/")
    updated = store.update_tracked_link(
        link["_id"],
        {"label": "updated", "settings": {"mode": "error", "status_code": 410}},
    )
    assert updated is not None
    assert updated["label"] == "updated"
    assert updated["settings"]["status_code"] == 410


def test_config_save_is_atomic_and_keeps_backup():
    first = config_store.save_config({"timezone": "UTC"})
    second = config_store.save_config({"timezone": "America/Chicago"})
    assert first["timezone"] == "UTC"
    assert second["timezone"] == "America/Chicago"
    backup = Path(config_store.CONFIG_FILE).with_suffix(".json.bak")
    assert json.loads(backup.read_text())["timezone"] == "UTC"


def test_proxy_headers_are_ignored_for_untrusted_peer():
    headers = {"X-Real-IP": "203.0.113.8"}
    assert resolve_client_ip("198.51.100.2", headers.get) == "198.51.100.2"


def test_capture_token_is_required_to_update_hit():
    hit_id = store.add_hit(
        {
            "ip": "203.0.113.8",
            "host": "example.com",
            "path": "/test",
            "method": "GET",
            "capture_token": "expected-token",
        }
    )
    with trap_app.app.test_client() as client:
        client.post("/capture", json={"hit_id": hit_id, "capture_token": "wrong", "language": "en"})
        assert not store.get_hit_by_id(hit_id)["client_fingerprint"]
        client.post(
            "/capture",
            json={"hit_id": hit_id, "capture_token": "expected-token", "language": "en"},
        )
        assert store.get_hit_by_id(hit_id)["client_fingerprint"]["capture_complete"] is True


def test_admin_auth_security_headers_and_health():
    admin_app.validate_admin_auth_config()
    with admin_app.app.test_client() as client:
        assert client.get("/").status_code == 401
        health = client.get("/healthz")
        assert health.status_code == 200
        response = client.get("/", headers=_basic_auth())
        assert response.status_code == 200
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers
        assert b"test-carto-key" in response.data
        status = client.get("/api/status", headers=_basic_auth())
        assert status.status_code == 200
        assert status.json["background"]["capacity"] >= status.json["background"]["workers"]
