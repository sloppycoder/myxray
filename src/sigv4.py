"""Minimal AWS Signature Version 4 signing, standard library only.

`boto3` cannot run inside a Cloudflare Python Worker (it relies on raw sockets /
urllib3). Instead we sign requests ourselves and send them with the JS `fetch`
API. Only `hashlib`, `hmac` and `datetime` are needed, all available in Pyodide.

Reference:
https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
"""

import hashlib
import hmac
from datetime import datetime, timezone

ALGORITHM = "AWS4-HMAC-SHA256"
_DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sign_request(
    *,
    method: str,
    host: str,
    region: str,
    service: str,
    body: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    content_type: str = _DEFAULT_CONTENT_TYPE,
) -> dict[str, str]:
    """Sign a request to `https://{host}/` and return the headers to send.

    Assumes the canonical URI is "/" with an empty query string (the EC2 Query
    API carries all parameters in the form-encoded request body).
    """
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    # Headers that participate in the signature, keyed by lowercase name.
    signed = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amzdate,
    }
    if session_token:
        signed["x-amz-security-token"] = session_token

    sorted_names = sorted(signed)
    signed_headers = ";".join(sorted_names)
    canonical_headers = "".join(f"{n}:{signed[n]}\n" for n in sorted_names)

    canonical_request = "\n".join(
        [method, "/", "", canonical_headers, signed_headers, payload_hash]
    )

    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amzdate,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    signing_key = _signing_key(secret_key, datestamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"{ALGORITHM} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    # `host` is set automatically by fetch, so we don't return it.
    headers = {
        "Content-Type": content_type,
        "X-Amz-Date": amzdate,
        "Authorization": authorization,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers
