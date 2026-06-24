"""Tiny EC2 client for Cloudflare Python Workers.

Talks to the EC2 Query API over the JS `fetch` interop (no boto3, no sockets),
signing every request with our stdlib SigV4 helper. Only two operations are
needed: DescribeInstances (to find the "xray" VM + its public IP) and
StartInstances (to boot it when it is stopped).
"""

import asyncio
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

from js import fetch, Object
from pyodide.ffi import to_js

from sigv4 import sign_request

# EC2 Query API version.
API_VERSION = "2016-11-15"

# How long to wait for a freshly-booted instance to reach "running" with a
# public IP, and how often to re-check.
BOOT_MAX_WAIT_SECONDS = 90
BOOT_POLL_INTERVAL_SECONDS = 5


class Ec2Error(Exception):
    """Raised when an EC2 API call fails or an instance never becomes ready."""


def _text(el, path):
    """Namespace-agnostic helper: return the text of the first matching child."""
    found = el.find(path)
    return found.text if found is not None else None


async def _ec2_call(region: str, creds: dict, params: dict) -> str:
    """POST a signed EC2 Query API request and return the XML response body."""
    host = f"ec2.{region}.amazonaws.com"
    url = f"https://{host}/"
    body = urlencode(params)

    headers = sign_request(
        method="POST",
        host=host,
        region=region,
        service="ec2",
        body=body,
        access_key=creds["access_key"],
        secret_key=creds["secret_key"],
        session_token=creds.get("session_token"),
    )

    options = to_js(
        {"method": "POST", "headers": headers, "body": body},
        dict_converter=Object.fromEntries,
    )
    resp = await fetch(url, options)
    text = await resp.text()
    if resp.status != 200:
        raise Ec2Error(f"EC2 {params.get('Action')} failed (HTTP {resp.status}): {text[:400]}")
    return text


async def describe_xray(region: str, creds: dict, name: str = "xray") -> dict | None:
    """Find the VM tagged Name=<name>. Returns {id, state, ip} or None if absent.

    Terminated / shutting-down instances are filtered out so we never return a
    dead instance.
    """
    text = await _ec2_call(
        region,
        creds,
        {
            "Action": "DescribeInstances",
            "Version": API_VERSION,
            "Filter.1.Name": "tag:Name",
            "Filter.1.Value.1": name,
            "Filter.2.Name": "instance-state-name",
            "Filter.2.Value.1": "pending",
            "Filter.2.Value.2": "running",
            "Filter.2.Value.3": "stopping",
            "Filter.2.Value.4": "stopped",
        },
    )

    root = ET.fromstring(text)
    # `{*}` is a namespace wildcard (Python 3.8+); EC2 responses are namespaced.
    inst = root.find(".//{*}instancesSet/{*}item")
    if inst is None:
        return None

    return {
        "id": _text(inst, "{*}instanceId"),
        "state": _text(inst, "{*}instanceState/{*}name"),
        "ip": _text(inst, "{*}ipAddress"),  # public IP; absent until running
    }


async def start_instance(region: str, creds: dict, instance_id: str) -> None:
    await _ec2_call(
        region,
        creds,
        {
            "Action": "StartInstances",
            "Version": API_VERSION,
            "InstanceId.1": instance_id,
        },
    )


async def resolve_xray_ip(
    region: str, creds: dict, name: str = "xray", boot: bool = False
) -> str | None:
    """Return the public IP of the "xray" VM.

    Returns the IP only when the VM is already running. Returns None when the VM
    is absent OR found-but-not-running (caller treats both as a hard error), so a
    routine subscription refresh never starts a stopped instance.

    When `boot` is True, a stopped VM is started and polled until it is running
    with a public IP. Raises Ec2Error if it never becomes ready in time.
    """
    info = await describe_xray(region, creds, name)
    if info is None:
        return None  # not found -> caller aborts

    if info["state"] == "running" and info["ip"]:
        return info["ip"]

    # Found but not running. Without an explicit boot request, do nothing — a
    # client opening / refreshing its subscription must not wake the instance.
    if not boot:
        return None

    # Boot it if it's stopped; "stopping" must finish before it can be started.
    if info["state"] == "stopped":
        await start_instance(region, creds, info["id"])

    waited = 0
    while waited < BOOT_MAX_WAIT_SECONDS:
        await asyncio.sleep(BOOT_POLL_INTERVAL_SECONDS)
        waited += BOOT_POLL_INTERVAL_SECONDS

        info = await describe_xray(region, creds, name)
        if info is None:
            return None  # vanished mid-boot (e.g. terminated)
        if info["state"] == "stopped":
            await start_instance(region, creds, info["id"])
        if info["state"] == "running" and info["ip"]:
            return info["ip"]

    state = info["state"] if info else "gone"
    raise Ec2Error(
        f"VM '{name}' did not become ready within {BOOT_MAX_WAIT_SECONDS}s (last state: {state})"
    )
