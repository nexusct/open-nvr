# Copyright (c) 2026 OpenNVR
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
"""UniFi Protect bulk import tests.

Run with:
    cd server && pytest tests/test_unifi_protect_import.py -v
"""

from __future__ import annotations

import os
import secrets
import sys
import types as _types
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "server"))

os.environ.setdefault("DATABASE_URL", "sqlite:///./_unifi_protect_import.db")
os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("MEDIAMTX_SECRET", secrets.token_hex(32))
os.environ.setdefault("INTERNAL_API_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())

_lm = _types.ModuleType("core.logging_config")


class _L:
    def __getattr__(self, _n):
        return lambda *a, **k: None


_lm.__getattr__ = lambda _n: _L()
_lm.setup_logging = lambda *a, **k: None
sys.modules["core.logging_config"] = _lm

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import core.auth as core_auth  # noqa: E402
from core.database import Base, get_db  # noqa: E402
from models import Camera, Permission, Role, RolePermission, User  # noqa: E402
from routers import cameras as cameras_router  # noqa: E402
from services.camera_service import CameraService  # noqa: E402
from services.unifi_protect_service import (  # noqa: E402
    UnifiProtectCameraCandidate,
    UnifiProtectService,
)


def test_camera_candidates_pick_main_and_substream():
    bootstrap = {
        "cameras": [
            {
                "name": "Front Door",
                "connectionHost": "10.0.0.20",
                "host": "10.0.0.21",
                "marketName": "G4 Bullet",
                "firmwareVersion": "1.2.3",
                "id": "cam-1",
                "mac": "aa:bb:cc",
                "channels": [
                    {
                        "enabled": True,
                        "isRtspEnabled": True,
                        "rtspAlias": "high",
                        "width": 1920,
                        "height": 1080,
                        "fps": 30,
                    },
                    {
                        "enabled": True,
                        "isRtspEnabled": True,
                        "rtspAlias": "low",
                        "width": 640,
                        "height": 360,
                        "fps": 15,
                    },
                ],
            }
        ]
    }

    candidates, failed = UnifiProtectService.camera_candidates(
        bootstrap, base_url="https://10.0.0.2"
    )

    assert failed == []
    assert len(candidates) == 1
    assert candidates[0].ip_address == "10.0.0.20"
    assert candidates[0].rtsp_url == "rtsps://10.0.0.2:7441/high"
    assert candidates[0].substream_url == "rtsps://10.0.0.2:7441/low"
    assert candidates[0].manufacturer == "Ubiquiti"
    assert candidates[0].model == "G4 Bullet"


def test_camera_candidates_report_rtsp_disabled_camera():
    bootstrap = {
        "cameras": [
            {
                "name": "Garage",
                "connectionHost": "10.0.0.30",
                "channels": [{"enabled": True, "isRtspEnabled": False, "rtspAlias": None}],
            }
        ]
    }

    candidates, failed = UnifiProtectService.camera_candidates(
        bootstrap, base_url="https://10.0.0.2"
    )

    assert candidates == []
    assert failed == [
        {
            "name": "Garage",
            "ip_address": "10.0.0.30",
            "message": "RTSP is not enabled for this Protect camera.",
        }
    ]


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(core_auth, "auth_logger", _L(), raising=False)
    monkeypatch.setattr(cameras_router, "camera_logger", _L(), raising=False)

    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(eng)
    session_local = sessionmaker(bind=eng, expire_on_commit=False)

    db = session_local()
    manage = Permission(name="cameras.manage", description="")
    viewer_role = Role(name="viewer", description="")
    operator_role = Role(name="operator", description="")
    db.add_all([manage, viewer_role, operator_role])
    db.flush()
    db.add(RolePermission(role_id=operator_role.id, permission_id=manage.id))

    def user(name, role):
        row = User(
            username=name,
            email=f"{name}@x",
            hashed_password="x",
            is_active=True,
            password_set=True,
            role_id=role.id,
        )
        db.add(row)
        db.flush()
        return row

    viewer = user("viewer", viewer_role)
    operator = user("operator", operator_role)
    db.add(
        Camera(
            name="Existing",
            ip_address="10.0.0.7",
            port=7441,
            owner_id=operator.id,
            rtsp_url="rtsps://10.0.0.2:7441/existing",
            is_active=True,
        )
    )
    db.commit()
    for u in (viewer, operator):
        db.refresh(u)
        _ = [p.name for p in (u.role.permissions or [])]
        db.expunge(u)
    db.close()

    app = FastAPI()
    app.include_router(cameras_router.router, prefix="/api/v1")

    def _db():
        s = session_local()
        try:
            yield s
        finally:
            s.close()

    current = {"user": viewer}
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[core_auth.get_current_active_user] = lambda: current["user"]
    with TestClient(app) as tc:
        yield tc, current, {"viewer": viewer, "operator": operator}, session_local


def test_import_route_needs_cameras_manage(env, monkeypatch):
    tc, current, users, _ = env

    async def _bootstrap(**_kwargs):
        return {"cameras": []}

    monkeypatch.setattr(
        UnifiProtectService, "fetch_bootstrap", staticmethod(_bootstrap)
    )

    response = tc.post(
        "/api/v1/cameras/import/unifi-protect",
        json={
            "base_url": "https://10.0.0.2",
            "username": "protect",
            "password": "Passw0rd!",
        },
    )
    assert response.status_code == 403

    current["user"] = users["operator"]
    response = tc.post(
        "/api/v1/cameras/import/unifi-protect",
        json={
            "base_url": "https://10.0.0.2",
            "username": "protect",
            "password": "Passw0rd!",
        },
    )
    assert response.status_code == 200, response.text


def test_import_route_imports_and_skips_duplicates(env, monkeypatch):
    tc, current, users, session_local = env
    current["user"] = users["operator"]

    async def _bootstrap(**_kwargs):
        return {"ok": True}

    def _candidates(_bootstrap, *, base_url):
        assert base_url == "https://10.0.0.2"
        return (
            [
                UnifiProtectCameraCandidate(
                    name="Existing Duplicate",
                    ip_address="10.0.0.7",
                    rtsp_url="rtsps://10.0.0.2:7441/existing",
                    substream_url=None,
                    manufacturer="Ubiquiti",
                    model="G4",
                    firmware_version="1.0",
                    serial_number="cam-1",
                    hardware_id="aa",
                ),
                UnifiProtectCameraCandidate(
                    name="Imported Camera",
                    ip_address="10.0.0.8",
                    rtsp_url="rtsps://10.0.0.2:7441/new-main",
                    substream_url="rtsps://10.0.0.2:7441/new-low",
                    manufacturer="Ubiquiti",
                    model="G5",
                    firmware_version="2.0",
                    serial_number="cam-2",
                    hardware_id="bb",
                ),
            ],
            [],
        )

    async def _create(db, camera_create, owner_id):
        cam = Camera(
            name=camera_create.name,
            ip_address=camera_create.ip_address,
            port=camera_create.port,
            username=camera_create.username,
            rtsp_url=camera_create.rtsp_url,
            substream_url=camera_create.substream_url,
            owner_id=owner_id,
            is_active=True,
            manufacturer=camera_create.manufacturer,
            model=camera_create.model,
        )
        cam.password = camera_create.password
        db.add(cam)
        db.commit()
        db.refresh(cam)
        return cam

    monkeypatch.setattr(
        UnifiProtectService, "fetch_bootstrap", staticmethod(_bootstrap)
    )
    monkeypatch.setattr(
        UnifiProtectService, "camera_candidates", staticmethod(_candidates)
    )
    monkeypatch.setattr(CameraService, "create_camera", staticmethod(_create))

    response = tc.post(
        "/api/v1/cameras/import/unifi-protect",
        json={
            "base_url": "https://10.0.0.2",
            "username": "protect",
            "password": "Passw0rd!",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total_seen"] == 2
    assert len(body["imported"]) == 1
    assert body["imported"][0]["name"] == "Imported Camera"
    assert len(body["skipped"]) == 1
    assert "Skipped duplicate" in body["skipped"][0]["message"]
    assert body["failed"] == []

    db = session_local()
    try:
        created = db.query(Camera).filter(Camera.ip_address == "10.0.0.8").one()
        assert created.rtsp_url == "rtsps://10.0.0.2:7441/new-main"
        assert created.substream_url == "rtsps://10.0.0.2:7441/new-low"
        assert created.username == "protect"
        assert created.password == "Passw0rd!"
    finally:
        db.close()


def test_import_route_skips_substream_duplicates(env, monkeypatch):
    tc, current, users, session_local = env
    current["user"] = users["operator"]

    db = session_local()
    db.add(
        Camera(
            name="Uses Same Low Stream",
            ip_address="10.0.0.55",
            port=7441,
            owner_id=users["operator"].id,
            rtsp_url="rtsps://10.0.0.2:7441/other-main",
            substream_url="rtsps://10.0.0.2:7441/shared-low",
            is_active=True,
        )
    )
    db.commit()
    db.close()

    async def _bootstrap(**_kwargs):
        return {"ok": True}

    def _candidates(_bootstrap, *, base_url):
        assert base_url == "https://10.0.0.2"
        return (
            [
                UnifiProtectCameraCandidate(
                    name="Would Duplicate Low Stream",
                    ip_address="10.0.0.8",
                    rtsp_url="rtsps://10.0.0.2:7441/new-main",
                    substream_url="rtsps://10.0.0.2:7441/shared-low",
                    manufacturer="Ubiquiti",
                    model="G5",
                    firmware_version="2.0",
                    serial_number="cam-3",
                    hardware_id="cc",
                )
            ],
            [],
        )

    async def _create(db, camera_create, owner_id):
        raise AssertionError("duplicate import should have been skipped before create")

    monkeypatch.setattr(
        UnifiProtectService, "fetch_bootstrap", staticmethod(_bootstrap)
    )
    monkeypatch.setattr(
        UnifiProtectService, "camera_candidates", staticmethod(_candidates)
    )
    monkeypatch.setattr(CameraService, "create_camera", staticmethod(_create))

    response = tc.post(
        "/api/v1/cameras/import/unifi-protect",
        json={
            "base_url": "https://10.0.0.2",
            "username": "protect",
            "password": "Passw0rd!",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["imported"] == []
    assert len(body["skipped"]) == 1
    assert "Skipped duplicate" in body["skipped"][0]["message"]
