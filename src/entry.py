"""myxray — Cloudflare Python Worker.

Path-based routing (the PIN selects a server profile from the XRAY_KV namespace):

  GET  /<pin>        Subscription endpoint. Returns the plain-text vless://… share
                     URL when the VM is running; 404 otherwise. NEVER boots the VM,
                     so a routine subscription refresh can't wake a stopped instance.
  GET  /<pin>/qr     Running → an HTML page with a scannable QR code. Not running →
                     a page with a "Start" button that boots the VM (via POST
                     /<pin>/boot), waits for it, then shows the QR.
  POST /<pin>/boot   Kick off StartInstances and return immediately (202). The QR
                     page polls GET /<pin> until the VM is ready.
"""

import json
from urllib.parse import urlparse

from workers import WorkerEntrypoint, Response

from config import build_share_url
from aws_ec2 import describe_xray, start_instance, resolve_xray_ip, Ec2Error
from render import qr_running_page, qr_start_page

# The resolved IP changes whenever the VM reboots, so responses must never be
# cached by the browser or any intermediary — always re-fetch a fresh result.
NO_CACHE = "no-store, no-cache, must-revalidate, max-age=0"


def _error(message: str, status: int) -> Response:
    return Response.json({"error": message}, status=status, headers={"cache-control": NO_CACHE})


def _env_str(env, name: str) -> str | None:
    """Read an env var / secret, returning None if it is missing or empty."""
    try:
        value = getattr(env, name)
    except AttributeError:
        return None
    return str(value) if value else None


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        path = urlparse(request.url).path
        segments = [s for s in path.split("/") if s]

        # Route: /<pin> or /<pin>/<action>. Anything else is unroutable.
        if not segments:
            return _error("missing pin in path: use /<pin>", 400)
        if len(segments) > 2:
            return _error("not found", 404)
        pin = segments[0]
        action = segments[1] if len(segments) == 2 else "url"
        if action not in ("url", "qr", "boot"):
            return _error(f"unknown action '{action}'; valid: qr, boot", 404)

        method = request.method.upper()
        expected = "POST" if action == "boot" else "GET"
        if method != expected:
            return _error(f"method {method} not allowed on this route", 405)

        # Resolve the PIN's server profile (single KV read).
        raw = await self.env.XRAY_KV.get(f"pin:{pin}")
        if raw is None:
            return _error("unknown pin", 403)
        profile = json.loads(raw)
        region = profile["region"]

        # AWS credentials come from secrets (never hard-coded).
        creds = self._aws_creds()
        if creds is None:
            return _error("server misconfigured: missing AWS credentials", 500)

        try:
            if action == "boot":
                return await self._handle_boot(region, creds)
            if action == "qr":
                return await self._handle_qr(profile, region, creds)
            return await self._handle_url(profile, region, creds)
        except Ec2Error as exc:
            return _error(f"aws error: {exc}", 502)
        except Exception as exc:  # defensive: never leak a raw stack trace
            return _error(f"unexpected error: {exc}", 500)

    def _aws_creds(self) -> dict | None:
        access_key = _env_str(self.env, "AWS_ACCESS_KEY_ID")
        secret_key = _env_str(self.env, "AWS_SECRET_ACCESS_KEY")
        if not access_key or not secret_key:
            return None
        return {
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": _env_str(self.env, "AWS_SESSION_TOKEN"),
        }

    async def _handle_url(self, profile: dict, region: str, creds: dict) -> Response:
        """GET /<pin>: plain-text share URL, only when the VM is running."""
        ip = await resolve_xray_ip(region, creds, boot=False)
        if ip is None:
            return _error(
                f"no running 'xray' VM in region {region}; open /<pin>/qr to start it",
                404,
            )
        url = build_share_url(profile, ip)
        return Response(
            url,
            headers={"content-type": "text/plain; charset=utf-8", "cache-control": NO_CACHE},
        )

    async def _handle_qr(self, profile: dict, region: str, creds: dict) -> Response:
        """GET /<pin>/qr: QR when running, else a Start page."""
        info = await describe_xray(region, creds)
        if info and info["state"] == "running" and info["ip"]:
            url = build_share_url(profile, info["ip"])
            return _html(qr_running_page(url, profile["name"]))
        # Not running (stopped/pending/stopping/absent) → offer to start it.
        return _html(qr_start_page(profile["name"]))

    async def _handle_boot(self, region: str, creds: dict) -> Response:
        """POST /<pin>/boot: fire StartInstances if stopped, return immediately."""
        info = await describe_xray(region, creds)
        if info is None:
            return _error("no 'xray' VM found in this region", 404)
        state = info["state"]
        if state == "running":
            return Response.json({"state": "running"}, headers={"cache-control": NO_CACHE})
        if state == "stopped":
            await start_instance(region, creds, info["id"])
            return Response.json({"state": "pending"}, status=202, headers={"cache-control": NO_CACHE})
        # pending (already booting) or stopping (must finish before it can start).
        return Response.json({"state": state}, status=202, headers={"cache-control": NO_CACHE})


def _html(body: str) -> Response:
    return Response(
        body,
        headers={"content-type": "text/html; charset=utf-8", "cache-control": NO_CACHE},
    )
