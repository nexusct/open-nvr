from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx


class UnifiProtectImportError(ValueError):
    def __init__(self, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class UnifiProtectCameraCandidate:
    name: str
    ip_address: str
    rtsp_url: str
    substream_url: str | None
    manufacturer: str | None
    model: str | None
    firmware_version: str | None
    serial_number: str | None
    hardware_id: str | None


def _normalize_base_url(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        raise UnifiProtectImportError("UniFi Protect controller URL is required.")
    if "://" not in text:
        text = f"https://{text}"
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.hostname:
        raise UnifiProtectImportError("UniFi Protect controller URL is invalid.")
    if parsed.scheme not in ("http", "https"):
        raise UnifiProtectImportError(
            "UniFi Protect controller URL must start with http:// or https://."
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def _controller_host(raw: str) -> str:
    parsed = urlparse(_normalize_base_url(raw))
    return parsed.hostname or ""


def _camera_name(camera: dict[str, Any]) -> str:
    return (
        str(camera.get("name") or "").strip()
        or str(camera.get("marketName") or "").strip()
        or str(camera.get("type") or "").strip()
        or str(camera.get("id") or "Unnamed Protect camera")
    )


def _channel_score(channel: dict[str, Any]) -> tuple[int, int, int]:
    width = int(channel.get("width") or 0)
    height = int(channel.get("height") or 0)
    fps = int(channel.get("fps") or 0)
    return (width * height, fps, width)


def _enabled_rtsp_channels(camera: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for channel in camera.get("channels") or []:
        if not isinstance(channel, dict):
            continue
        if not channel.get("enabled"):
            continue
        alias = channel.get("rtspAlias")
        if not channel.get("isRtspEnabled") or not alias:
            continue
        rows.append(channel)
    return rows


def _protect_stream_url(controller_host: str, alias: str) -> str:
    safe_alias = quote(str(alias).strip(), safe="")
    return f"rtsps://{controller_host}:7441/{safe_alias}"


class UnifiProtectService:
    @staticmethod
    def controller_host(base_url: str) -> str:
        return _controller_host(base_url)

    @staticmethod
    async def fetch_bootstrap(
        *, base_url: str, username: str, password: str, verify_tls: bool = False
    ) -> dict[str, Any]:
        normalized = _normalize_base_url(base_url)
        headers = {"Accept": "application/json"}
        async with httpx.AsyncClient(
            base_url=normalized,
            follow_redirects=True,
            timeout=20.0,
            verify=verify_tls,
            headers=headers,
        ) as client:
            try:
                login = await client.post(
                    "/api/auth/login",
                    json={"username": username, "password": password},
                )
            except httpx.RequestError as exc:
                raise UnifiProtectImportError(
                    "Couldn't reach the UniFi Protect controller.",
                    status_code=502,
                ) from exc
            if login.status_code in (401, 403):
                raise UnifiProtectImportError(
                    "UniFi Protect authentication failed. Check the username and password."
                )
            try:
                login.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise UnifiProtectImportError(
                    f"UniFi Protect login failed (HTTP {exc.response.status_code}).",
                    status_code=502,
                ) from exc

            try:
                bootstrap = await client.get("/proxy/protect/api/bootstrap")
            except httpx.RequestError as exc:
                raise UnifiProtectImportError(
                    "UniFi Protect authenticated, but the bootstrap request failed.",
                    status_code=502,
                ) from exc
            if bootstrap.status_code in (401, 403):
                raise UnifiProtectImportError(
                    "UniFi Protect accepted the login but refused bootstrap access."
                )
            try:
                bootstrap.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise UnifiProtectImportError(
                    f"UniFi Protect bootstrap failed (HTTP {exc.response.status_code}).",
                    status_code=502,
                ) from exc
            try:
                data = bootstrap.json()
            except ValueError as exc:
                raise UnifiProtectImportError(
                    "UniFi Protect returned invalid bootstrap JSON.",
                    status_code=502,
                ) from exc
        if not isinstance(data, dict):
            raise UnifiProtectImportError(
                "UniFi Protect bootstrap response had an unexpected shape.",
                status_code=502,
            )
        return data

    @staticmethod
    def camera_candidates(
        bootstrap: dict[str, Any], *, base_url: str
    ) -> tuple[list[UnifiProtectCameraCandidate], list[dict[str, str | None]]]:
        raw_cameras = bootstrap.get("cameras")
        if not isinstance(raw_cameras, list):
            raw_cameras = (bootstrap.get("data") or {}).get("cameras")
        if not isinstance(raw_cameras, list):
            raise UnifiProtectImportError(
                "UniFi Protect bootstrap did not include a camera list.",
                status_code=502,
            )

        controller_host = _controller_host(base_url)
        candidates: list[UnifiProtectCameraCandidate] = []
        failed: list[dict[str, str | None]] = []

        for raw in raw_cameras:
            if not isinstance(raw, dict):
                continue
            name = _camera_name(raw)
            ip_address = str(raw.get("connectionHost") or raw.get("host") or "").strip()
            if not ip_address:
                failed.append(
                    {
                        "name": name,
                        "ip_address": None,
                        "message": "Camera has no usable IP address in the Protect bootstrap.",
                    }
                )
                continue

            channels = _enabled_rtsp_channels(raw)
            if not channels:
                failed.append(
                    {
                        "name": name,
                        "ip_address": ip_address,
                        "message": "RTSP is not enabled for this Protect camera.",
                    }
                )
                continue

            ordered = sorted(channels, key=_channel_score, reverse=True)
            main = ordered[0]
            substream = next(
                (
                    ch
                    for ch in reversed(ordered)
                    if ch.get("rtspAlias") and ch.get("rtspAlias") != main.get("rtspAlias")
                ),
                None,
            )
            model = str(raw.get("marketName") or raw.get("type") or "").strip() or None
            candidates.append(
                UnifiProtectCameraCandidate(
                    name=name,
                    ip_address=ip_address,
                    rtsp_url=_protect_stream_url(controller_host, str(main["rtspAlias"])),
                    substream_url=(
                        _protect_stream_url(controller_host, str(substream["rtspAlias"]))
                        if substream and substream.get("rtspAlias")
                        else None
                    ),
                    manufacturer="Ubiquiti",
                    model=model,
                    firmware_version=(
                        str(raw.get("firmwareVersion")).strip()
                        if raw.get("firmwareVersion")
                        else None
                    ),
                    serial_number=(
                        str(raw.get("id")).strip() if raw.get("id") else None
                    ),
                    hardware_id=(
                        str(raw.get("mac")).strip() if raw.get("mac") else None
                    ),
                )
            )

        return candidates, failed
