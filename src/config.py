"""Static configuration for the myxray worker.

Each PIN maps to a complete server profile: the AWS region to find the VM in,
the Xray user UUID, the server's REALITY public key + short id, and the display
name shown in the client. Those per-server profiles live in the XRAY_KV
namespace (one JSON value per "pin:<PIN>" key), managed by
scripts/xray.py; entry.py reads them. The connection parameters
common to every server live in build_share_url() below.
"""

from urllib.parse import urlencode, quote

# --------------------------------------------------------------------------- #
# Xray (VLESS + REALITY) parameters common to every server                     #
# --------------------------------------------------------------------------- #
XRAY_PORT = 443
SNI = "www.akamai.com"
FINGERPRINT = "chrome"


def build_share_url(profile: dict, ip: str) -> str:
    """Build a VLESS share URL for `profile` at the resolved `ip`.

    Shape: vless://<uuid>@<ip>:<port>?<params>#<name>
    Key order in `params` is preserved in the generated query string.
    """
    params = {
        "encryption": "none",
        "flow": "xtls-rprx-vision",
        "security": "reality",
        "sni": SNI,
        "fp": FINGERPRINT,
        "pbk": profile["pbk"],
        "sid": profile["sid"],
        "type": "tcp",
    }
    # Drop any empty-valued params for a cleaner link.
    params = {k: v for k, v in params.items() if v != ""}
    query = urlencode(params)
    fragment = quote(profile["name"])
    return f"vless://{profile['uuid']}@{ip}:{XRAY_PORT}?{query}#{fragment}"
