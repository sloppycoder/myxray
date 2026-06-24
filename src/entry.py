"""myxray — Cloudflare Python Worker.

Flow:
  1. Read ?pin= from the request URL and look up its server profile (AWS region +
     Xray credentials). Reject unknown PINs.
  2. Find the VM tagged Name=xray in that profile's region. Return its public IP
     only if it is already running; a non-running (or absent) VM is a 404. Pass
     ?boot=1 to explicitly start a stopped VM and wait for it.
  3. Combine the public IP with the profile's Xray parameters into a share URL.
  4. Return the URL as plain text (?mode=url, default) or an HTML page with a QR
     code (?mode=qr) for an Xray client (e.g. Hiddify).
"""

import json
from urllib.parse import urlparse, parse_qs

from workers import WorkerEntrypoint, Response

from config import build_share_url
from aws_ec2 import resolve_xray_ip, Ec2Error
from render import qr_html_page

VALID_MODES = ("url", "qr")

# The resolved IP changes whenever the VM reboots, so responses must never be
# cached by the browser or any intermediary — always re-fetch a fresh result.
NO_CACHE = "no-store, no-cache, must-revalidate, max-age=0"


def _error(message: str, status: int) -> Response:
    return Response.json({"error": message}, status=status)


def _env_str(env, name: str) -> str | None:
    """Read an env var / secret, returning None if it is missing or empty."""
    try:
        value = getattr(env, name)
    except AttributeError:
        return None
    return str(value) if value else None


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        params = parse_qs(urlparse(request.url).query)
        pin = (params.get("pin") or [None])[0]
        mode = (params.get("mode") or ["url"])[0].lower()
        # Opt-in: only ?boot=1 may start a stopped VM. A plain subscription
        # refresh must never wake the instance.
        boot = (params.get("boot") or ["0"])[0].lower() in ("1", "true", "yes", "on")

        # 1. Validate inputs and resolve the PIN's server profile.
        if not pin:
            return _error("missing required parameter: pin", 400)
        if mode not in VALID_MODES:
            return _error(f"unknown mode '{mode}'; valid values: {list(VALID_MODES)}", 400)

        # Profiles live in the XRAY_KV namespace, one JSON value per "pin:<PIN>"
        # key (see wrangler.jsonc). Each lookup is a single KV read.
        raw = await self.env.XRAY_KV.get(f"pin:{pin}")
        if raw is None:
            return _error("unknown pin", 403)
        profile = json.loads(raw)
        region = profile["region"]

        # AWS credentials come from secrets (never hard-coded).
        access_key = _env_str(self.env, "AWS_ACCESS_KEY_ID")
        secret_key = _env_str(self.env, "AWS_SECRET_ACCESS_KEY")
        if not access_key or not secret_key:
            return _error("server misconfigured: missing AWS credentials", 500)
        creds = {
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": _env_str(self.env, "AWS_SESSION_TOKEN"),
        }

        # 2. Find the "xray" VM and get its public IP. Only ?boot=1 may start a
        #    stopped VM; otherwise a non-running VM is reported as 404.
        try:
            ip = await resolve_xray_ip(region, creds, boot=boot)
        except Ec2Error as exc:
            return _error(f"aws error: {exc}", 502)
        except Exception as exc:  # defensive: never leak a raw stack trace
            return _error(f"unexpected error: {exc}", 500)

        if ip is None:
            return _error(
                f"no running 'xray' VM in region {region}; append &boot=1 to start it",
                404,
            )

        # 3 + 4. Build the Xray share URL and return it in the requested mode.
        url = build_share_url(profile, ip)
        if mode == "qr":
            html = qr_html_page(url, profile["name"])
            return Response(
                html,
                headers={
                    "content-type": "text/html; charset=utf-8",
                    "cache-control": NO_CACHE,
                },
            )
        return Response(
            url,
            headers={
                "content-type": "text/plain; charset=utf-8",
                "cache-control": NO_CACHE,
            },
        )
