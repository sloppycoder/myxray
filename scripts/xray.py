#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["boto3>=1.34", "cryptography>=42", "python-dotenv>=1.0"]
# ///
"""Manage Xray (VLESS + REALITY) servers on AWS.

One tool, five operations (one VM per region, tagged Name=xray):

    new      provision a fresh VM + register its profile in Cloudflare KV
    status   show the VM's state, public IP, and (with KV) its PIN
    start    start the stopped VM
    stop     stop the running VM
    delete   terminate the VM and (with KV) delete its profile

AWS is the source of truth; Cloudflare KV is an OPTIONAL convenience layer:
  * --region always works without KV (the VM is found by its Name=xray tag).
  * --name / --pin are KV-backed aliases for a region, so they require KV;
    if KV is unreachable, the op tells you to select with --region instead.
  * `new` writes the client profile to KV when reachable (and enforces unique
    display names); if KV is down it still provisions the VM and prints the
    profile + the wrangler command to add it later.

No SSH for setup: the UUID, REALITY x25519 keypair, and short id are generated
locally and baked into a cloud-init user-data script that installs Xray, writes
config.json (logging to /var/log/xray), and enables the service at first boot.
SSH access (for maintenance) uses the first existing EC2 key pair in the region.

AWS credentials are loaded from .secrets (the xray-ops user) via python-dotenv.

Run with uv:
    uv run scripts/xray.py new    --region us-west-2 --name US
    uv run scripts/xray.py status --region us-west-2
    uv run scripts/xray.py status --pin 2580            # needs KV
    uv run scripts/xray.py stop   --name US             # needs KV
    uv run scripts/xray.py delete --region us-west-2 --yes

NOTE: tune render_xray_config() if your server template differs. The REALITY /
VLESS params below (SNI, PORT, FLOW) MUST match src/config.py.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import uuid as uuidlib
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
SECRETS_FILE = REPO_ROOT / ".secrets"

# Base URL of your deployed Worker — used ONLY to print ready-to-run curl/QR
# commands. Kept out of source (this is a public repo): set XRAY_WORKER_URL in
# your environment (or .secrets) to your real URL; otherwise a placeholder is
# shown. Resolved at call time, after .secrets is loaded.
WORKER_URL_PLACEHOLDER = "https://xsubs.<your-subdomain>.workers.dev"

# Per-server profiles live in this Cloudflare KV namespace (binding in
# wrangler.jsonc), one JSON value per "pin:<PIN>" key. We read/write it by
# shelling out to wrangler (via pywrangler), reusing your Cloudflare login.
KV_BINDING = "XRAY_KV"
KV_KEY_PREFIX = "pin:"
WRANGLER = ["uv", "run", "pywrangler"]

# Keys every client profile must carry (region for the VM lookup; the rest build
# the vless:// URL in src/config.py). Used to validate `import`.
REQUIRED_PROFILE_KEYS = ("region", "name", "uuid", "pbk", "sid")

# Debian's official AWS account that publishes the Debian AMIs.
DEBIAN_OWNER = "136693071363"
DEBIAN_RELEASES = ["13", "12"]  # newest first

XRAY_CONFIG_PATH = "/usr/local/etc/xray/config.json"
XRAY_LOG_DIR = "/var/log/xray"
XRAY_INSTALL_URL = "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# REQUIRED, not configurable: the Cloudflare Worker finds the VM by this exact
# Name tag (see src/aws_ec2.py). A different tag would make the VM invisible.
XRAY_NAME_TAG = "xray"

# Fixed provisioning defaults (previously CLI flags). Not worth a knob — change
# them here on the rare occasion you need to.
ARCH = "arm64"            # arm64 -> t4g.micro (cheapest); x86_64 -> t3.micro
INSTANCE_TYPE = "t4g.micro"
SG_NAME = "xray-sg"       # AWS forbids security-group names starting with "sg-"

# REALITY / VLESS params baked into the server config. These MUST match the
# client-side values in src/config.py (SNI, XRAY_PORT) and the "flow" in
# build_share_url() there, or the generated share URL won't connect.
SNI = "www.akamai.com"
PORT = 443
FLOW = "xtls-rprx-vision"

# Friendly city names accepted by --region, mapped to their AWS region. Only
# these are translated; any other --region value is passed through unchanged
# (e.g. an explicit region id like "us-east-1").
CITY_REGIONS = {
    "tokyo": "ap-northeast-1",
    "osaka": "ap-northeast-3",
    "singapore": "ap-southeast-1",
    "oregon": "us-west-2",
    "los_angeles": "us-west-1",
    "hong_kong": "ap-east-1",
}


def log(msg: str) -> None:
    print(f"==> {msg}", flush=True)


def die(msg: str) -> None:
    print(f"!!! {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Local secret generation                                                      #
# --------------------------------------------------------------------------- #
def gen_reality_keypair() -> tuple[str, str]:
    """A REALITY x25519 keypair as (private, public), base64url without padding
    — identical to `xray x25519`."""
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return b64u(raw_priv), b64u(raw_pub)


def select_key_pair(ec2) -> str:
    """Use an existing EC2 key pair in this region — the first available.
    Aborts if none exists (create one, and keep its .pem, before provisioning)."""
    kps = ec2.describe_key_pairs().get("KeyPairs", [])
    if not kps:
        die("no EC2 key pair exists in this region — create one (and keep its "
            ".pem) before provisioning")
    chosen = kps[0]["KeyName"]
    log(f"using first available key pair: {chosen}")
    return chosen


# --------------------------------------------------------------------------- #
# config.json template (TUNE for your server)                                  #
# --------------------------------------------------------------------------- #
def render_xray_config(uuid: str, private_key: str, short_id: str,
                       sni: str, port: int, flow: str) -> str:
    server_names = [sni]
    parts = sni.split(".")
    if len(parts) > 2:
        apex = ".".join(parts[-2:])
        if apex not in server_names:
            server_names.append(apex)
    return json.dumps(
        {
            "log": {
                "loglevel": "warning",
                "access": f"{XRAY_LOG_DIR}/access.log",
                "error": f"{XRAY_LOG_DIR}/error.log",
            },
            "inbounds": [
                {
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": uuid, "flow": flow}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": f"{sni}:443",
                            "serverNames": server_names,
                            "privateKey": private_key,
                            "shortIds": [short_id],
                        },
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls"],
                    },
                }
            ],
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "blocked"},
            ],
            "routing": {
                "rules": [
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                ],
            },
        },
        indent=2,
    )


def build_user_data(config_json: str) -> str:
    """A cloud-init shell script: install Xray, write the config, and start the
    service. SSH access is provided by the EC2 key pair (KeyName at launch)."""
    return f"""#!/bin/bash
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates
bash -c "$(curl -fsSL {XRAY_INSTALL_URL})" @ install
install -d -m 0750 {XRAY_LOG_DIR}
U=$(systemctl show -p User --value xray 2>/dev/null); G=$(systemctl show -p Group --value xray 2>/dev/null)
chown "${{U:-nobody}}:${{G:-nogroup}}" {XRAY_LOG_DIR}
cat > {XRAY_CONFIG_PATH} <<'XRAYCONF'
{config_json}
XRAYCONF
systemctl enable xray
systemctl restart xray
"""


# --------------------------------------------------------------------------- #
# AWS helpers                                                                  #
# --------------------------------------------------------------------------- #
def connect_aws(region: str):
    """Verify credentials and return an EC2 client bound to `region`."""
    try:
        ident = boto3.client("sts", region_name=region).get_caller_identity()
        log(f"AWS identity: {ident['Arn']}")
    except Exception as exc:
        die(f"no usable AWS credentials ({exc})")
    return boto3.client("ec2", region_name=region)


def existing_xray(ec2):
    """The one Name=xray instance in this region (any non-terminated state), or
    None."""
    r = ec2.describe_instances(Filters=[
        {"Name": "tag:Name", "Values": [XRAY_NAME_TAG]},
        {"Name": "instance-state-name",
         "Values": ["pending", "running", "stopping", "stopped"]},
    ])
    for res in r["Reservations"]:
        for inst in res["Instances"]:
            return inst
    return None


def find_internet_facing_subnet(ec2):
    """Return (subnet_id, vpc_id) of an internet-facing subnet, preferring one
    that auto-assigns public IPs. Raises if none found."""
    rtbs = ec2.describe_route_tables()["RouteTables"]
    subnets = ec2.describe_subnets()["Subnets"]

    def rt_is_public(rt):
        return any(r.get("DestinationCidrBlock") == "0.0.0.0/0"
                   and str(r.get("GatewayId", "")).startswith("igw-")
                   for r in rt.get("Routes", []))

    explicit, public, main_public_vpcs = set(), set(), set()
    for rt in rtbs:
        pub = rt_is_public(rt)
        for a in rt.get("Associations", []):
            if a.get("SubnetId"):
                explicit.add(a["SubnetId"])
                if pub:
                    public.add(a["SubnetId"])
            elif a.get("Main") and pub:
                main_public_vpcs.add(rt.get("VpcId"))
    for s in subnets:
        if s["SubnetId"] not in explicit and s.get("VpcId") in main_public_vpcs:
            public.add(s["SubnetId"])

    if not public:
        die("no internet-facing subnet found in this region")
    by_id = {s["SubnetId"]: s for s in subnets}
    chosen = sorted(public, key=lambda sid: not by_id[sid].get("MapPublicIpOnLaunch"))[0]
    return chosen, by_id[chosen]["VpcId"]


def ensure_security_group(ec2, vpc_id: str, sg_name: str, port: int,
                          ssh_cidr: str, dry_run: bool) -> str:
    groups = ec2.describe_security_groups(Filters=[
        {"Name": "group-name", "Values": [sg_name]},
        {"Name": "vpc-id", "Values": [vpc_id]},
    ])["SecurityGroups"]
    if groups:
        sg_id = groups[0]["GroupId"]
        log(f"security group {sg_name} exists: {sg_id}")
    else:
        if dry_run:
            log(f"[dry-run] would create security group {sg_name} in {vpc_id}")
            return "sg-DRYRUN"
        sg_id = ec2.create_security_group(
            GroupName=sg_name, Description="Xray server (myxray)", VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group",
                                "Tags": [{"Key": "Name", "Value": sg_name},
                                         {"Key": "app", "Value": "myxray"}]}],
        )["GroupId"]
        log(f"created security group {sg_name}: {sg_id}")

    rules = [
        (port, "0.0.0.0/0", "xray"),
        (22, ssh_cidr, "ssh"),
    ]
    for p, cidr, desc in rules:
        if dry_run:
            log(f"[dry-run] would allow {desc} tcp/{p} from {cidr}")
            continue
        try:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": p, "ToPort": p,
                "IpRanges": [{"CidrIp": cidr, "Description": f"myxray {desc}"}],
            }])
            log(f"allowed {desc} tcp/{p} from {cidr}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                log(f"{desc} tcp/{p} already present")
            else:
                raise
    return sg_id


def latest_debian_ami(ec2, arch: str) -> str:
    deb_arch = {"arm64": "arm64", "x86_64": "amd64"}[arch]
    for rel in DEBIAN_RELEASES:
        imgs = ec2.describe_images(Owners=[DEBIAN_OWNER], Filters=[
            {"Name": "name", "Values": [f"debian-{rel}-{deb_arch}-*"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": [arch]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ])["Images"]
        imgs = [i for i in imgs if "backports" not in i["Name"]]
        if imgs:
            newest = max(imgs, key=lambda i: i["CreationDate"])
            log(f"Debian {rel} {deb_arch} AMI: {newest['ImageId']} ({newest['Name']})")
            return newest["ImageId"]
    die(f"no Debian AMI found for arch {arch}")


# --------------------------------------------------------------------------- #
# Cloudflare KV (optional): one JSON value per "pin:<PIN>" key                 #
# --------------------------------------------------------------------------- #
def _wrangler_kv(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run `pywrangler kv <args>` from the repo root, capturing output."""
    return subprocess.run(
        WRANGLER + ["kv", *args], cwd=REPO_ROOT,
        check=check, capture_output=True, text=True,
    )


def _wrangler_json(out: str):
    """Parse JSON from wrangler stdout, skipping pywrangler's leading
    'INFO Passing command to npx wrangler: ...' banner (printed before the
    actual output). Returns None if no JSON value is present."""
    for i, ch in enumerate(out):
        if ch in "[{":
            return json.loads(out[i:])
    return None


_KV_OK: bool | None = None


def kv_reachable() -> bool:
    """Whether Cloudflare KV can be read (wrangler present + logged in). Probed
    once and memoized; failures are non-fatal — the caller degrades to AWS-only."""
    global _KV_OK
    if _KV_OK is None:
        try:
            res = _wrangler_kv("key", "list", "--binding", KV_BINDING, "--remote",
                               check=False)
            _KV_OK = res.returncode == 0
            if not _KV_OK:
                log("KV not reachable (wrangler error) — continuing AWS-only.")
        except FileNotFoundError:
            _KV_OK = False
            log("KV not reachable (uv/wrangler not found) — continuing AWS-only.")
    return _KV_OK


def kv_list_pins() -> set[str]:
    """All PINs currently registered in the XRAY_KV namespace."""
    out = _wrangler_kv("key", "list", "--binding", KV_BINDING, "--remote").stdout
    keys = _wrangler_json(out) or []
    return {k["name"][len(KV_KEY_PREFIX):] for k in keys
            if k.get("name", "").startswith(KV_KEY_PREFIX)}


def kv_get_profile(pin: str) -> dict | None:
    """The profile stored at pin:<pin>, or None if the key is absent."""
    res = _wrangler_kv("key", "get", "--binding", KV_BINDING, "--remote",
                       f"{KV_KEY_PREFIX}{pin}", check=False)
    if res.returncode != 0:
        return None
    prof = _wrangler_json(res.stdout)
    return prof if isinstance(prof, dict) else None


def kv_put_profile(pin: str, profile: dict) -> None:
    """Write profile to pin:<pin> in the XRAY_KV namespace."""
    _wrangler_kv("key", "put", "--binding", KV_BINDING, "--remote",
                 f"{KV_KEY_PREFIX}{pin}", json.dumps(profile))


def kv_delete_profile(pin: str) -> None:
    """Delete pin:<pin> from the XRAY_KV namespace."""
    _wrangler_kv("key", "delete", "--binding", KV_BINDING, "--remote",
                 f"{KV_KEY_PREFIX}{pin}")


def pin_for_region(region: str) -> str | None:
    """The PIN whose profile targets `region` (from KV), or None. Assumes KV is
    reachable (caller checks kv_reachable())."""
    try:
        for pin in kv_list_pins():
            prof = kv_get_profile(pin)
            if prof and prof.get("region") == region:
                return pin
    except Exception as exc:
        log(f"warning: could not query KV for the region's PIN ({exc})")
    return None


def generate_pin(existing: set[str]) -> str:
    """A random 5-digit numeric PIN (10000-99999) not already in `existing`."""
    for _ in range(100000):
        pin = str(secrets.randbelow(90000) + 10000)
        if pin not in existing:
            return pin
    die("could not generate a unique PIN")


# --------------------------------------------------------------------------- #
# Target resolution: a selector (--region | --name | --pin) -> (region, pin?)  #
# --------------------------------------------------------------------------- #
def apply_city_alias(region: str) -> str:
    mapped = CITY_REGIONS.get(region.lower())
    if mapped:
        log(f"region: {region!r} -> {mapped}")
        return mapped
    return region


def resolve_target(args) -> tuple[str, str | None]:
    """Map the chosen selector to (region, pin). --region needs no KV (pin is
    then unknown, returned as None). --name/--pin require KV; abort if it's down
    or the selector matches no / multiple servers."""
    if args.region:
        return apply_city_alias(args.region), None

    if args.pin:
        if not kv_reachable():
            die("--pin selection needs Cloudflare KV, which is unreachable — "
                "select with --region instead.")
        prof = kv_get_profile(args.pin)
        if not prof:
            die(f"no KV profile for pin {args.pin}")
        return prof["region"], args.pin

    # args.name
    if not kv_reachable():
        die("--name selection needs Cloudflare KV, which is unreachable — "
            "select with --region instead.")
    matches = []
    for pin in kv_list_pins():
        prof = kv_get_profile(pin)
        if prof and prof.get("name") == args.name:
            matches.append((prof["region"], pin))
    if not matches:
        die(f"no server named {args.name!r} in KV")
    if len(matches) > 1:
        die(f"name {args.name!r} matches multiple pins {[p for _, p in matches]} "
            f"— select with --pin")
    return matches[0]


def worker_base() -> str:
    return os.environ.get("XRAY_WORKER_URL", WORKER_URL_PLACEHOLDER).rstrip("/")


def client_url(pin: str) -> str:
    """Subscription / plain-URL endpoint: GET /<pin>."""
    return f"{worker_base()}/{pin}"


def qr_url(pin: str) -> str:
    """QR-page endpoint (with a Start button when the VM is stopped): /<pin>/qr."""
    return f"{worker_base()}/{pin}/qr"


# --------------------------------------------------------------------------- #
# Commands                                                                     #
# --------------------------------------------------------------------------- #
def cmd_new(args) -> None:
    region = apply_city_alias(args.region)
    ec2 = connect_aws(region)

    log(f"region {region}: checking for an existing VM tagged Name={XRAY_NAME_TAG} ...")
    if existing_xray(ec2):
        die(f"a VM tagged Name={XRAY_NAME_TAG} already exists in {region} — one per "
            f"region. Use `status`, `start`, or `delete` instead.")
    log("none found.")

    key_name = select_key_pair(ec2)

    # KV is optional. When reachable, enforce unique names + a free PIN.
    kv_ok = kv_reachable()
    existing = kv_list_pins() if kv_ok else set()
    if kv_ok:
        for epin in existing:
            prof = kv_get_profile(epin)
            if prof and prof.get("name") == args.name:
                die(f"name {args.name!r} is already used by pin {epin} — display "
                    f"names must be unique.")
        if args.pin and args.pin in existing:
            die(f"pin {args.pin} is already in use — choose another or omit --pin.")
    elif args.pin:
        log("note: KV unreachable — cannot verify the PIN is unique.")
    pin = args.pin or generate_pin(existing)
    log(f"pin: {pin}")

    subnet_id, vpc_id = find_internet_facing_subnet(ec2)
    log(f"internet-facing subnet: {subnet_id} (vpc {vpc_id})")
    sg_id = ensure_security_group(ec2, vpc_id, SG_NAME, PORT, args.ssh_cidr, args.dry_run)
    ami = latest_debian_ami(ec2, ARCH)

    if args.dry_run:
        log("[dry-run] would launch:")
        print(f"    pin={pin} name={args.name} ami={ami} type={INSTANCE_TYPE} key={key_name} "
              f"subnet={subnet_id} sg={sg_id} tag Name={XRAY_NAME_TAG}")
        if not kv_ok:
            log("[dry-run] KV unreachable — no profile would be written.")
        log("[dry-run] stopping before any VM is launched.")
        return

    if not args.yes:
        ans = input(f"Launch {INSTANCE_TYPE} ({ARCH}) in {region} as Name={XRAY_NAME_TAG}? [y/N] ")
        if ans.strip().lower() not in ("y", "yes"):
            die("aborted by user")

    # generate the server's secrets locally
    uuid = str(uuidlib.uuid4())
    private_key, public_key = gen_reality_keypair()
    short_id = secrets.token_hex(8)
    config = render_xray_config(uuid, private_key, short_id, SNI, PORT, FLOW)
    user_data = build_user_data(config)

    log("launching instance ...")
    inst = ec2.run_instances(
        ImageId=ami, InstanceType=INSTANCE_TYPE, KeyName=key_name,
        MinCount=1, MaxCount=1, UserData=user_data,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
                            "AssociatePublicIpAddress": True, "DeleteOnTermination": True}],
        TagSpecifications=[{"ResourceType": "instance",
                            "Tags": [{"Key": "Name", "Value": XRAY_NAME_TAG},
                                     {"Key": "app", "Value": "myxray"}]}],
        MetadataOptions={"HttpTokens": "required"},
    )["Instances"][0]
    iid = inst["InstanceId"]
    log(f"launched {iid}; waiting for it to run ...")
    ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
    desc = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    ip = desc.get("PublicIpAddress")
    log(f"running at {ip}")

    profile = {
        "region": region, "name": args.name,
        "uuid": uuid, "pbk": public_key, "sid": short_id,
    }
    if kv_ok:
        kv_put_profile(pin, profile)
        log(f"wrote KV {KV_KEY_PREFIX}{pin} (binding {KV_BINDING}) — pin {pin} -> {args.name}")

    print("\n" + "=" * 76)
    print(f"DONE — instance {iid} launched at {ip}  (pin {pin}, {args.name}, {region}).")
    print(f"  uuid={uuid}")
    print(f"  pbk={public_key}  sid={short_id}")
    if kv_ok:
        print("\nNEXT STEPS: profile is in KV (no redeploy). Verify once Xray is up")
        print("  (~1-2 min after boot; allow a few s for KV to propagate):")
        print(f"       curl '{client_url(pin)}'                # subscription URL")
        print(f"       open '{qr_url(pin)}'   # QR page (scan from the client)")
    else:
        print("\nNEXT STEPS: KV was UNREACHABLE — no client profile was written, so the")
        print("  Worker can't serve this server yet. Add the profile when you have")
        print("  Cloudflare access:")
        print(f"       uv run pywrangler kv key put --binding {KV_BINDING} --remote \\")
        print(f"         {KV_KEY_PREFIX}{pin} '{json.dumps(profile)}'")
    print("=" * 76)


def cmd_status(args) -> None:
    region, pin = resolve_target(args)
    ec2 = connect_aws(region)
    inst = existing_xray(ec2)
    if pin is None and kv_reachable():
        pin = pin_for_region(region)

    print("\n" + "=" * 76)
    if not inst:
        print(f"NO VM — nothing tagged Name={XRAY_NAME_TAG} in {region}.")
        if pin:
            print(f"  (A KV profile exists: pin {pin} -> {region}. Run `new` to provision,")
            print("   or `delete` to remove the stale profile.)")
    else:
        iid = inst["InstanceId"]
        state = inst["State"]["Name"]
        ip = inst.get("PublicIpAddress")
        print(f"{state.upper()} — instance {iid} in {region}" + (f" at {ip}" if ip else ""))
        if pin:
            print(f"  pin {pin}")
            if state == "running" and ip:
                print("\nClient config (fresh IP):")
                print(f"       curl '{client_url(pin)}'                # subscription URL")
                print(f"       open '{qr_url(pin)}'   # QR page")
        elif kv_reachable():
            print("  (no KV profile targets this region — clients can't select it yet)")
    print("=" * 76)


def cmd_start(args) -> None:
    region, pin = resolve_target(args)
    ec2 = connect_aws(region)
    inst = existing_xray(ec2)
    if not inst:
        die(f"no VM tagged Name={XRAY_NAME_TAG} in {region}")
    iid = inst["InstanceId"]
    state = inst["State"]["Name"]

    if state == "running":
        ip = inst.get("PublicIpAddress")
        log(f"{iid} is already running at {ip} (nothing to do).")
    elif state == "stopped":
        if args.dry_run:
            log(f"[dry-run] would start {iid} and wait for it to run.")
            return
        log(f"starting {iid} ...")
        ec2.start_instances(InstanceIds=[iid])
        ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
        desc = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        ip = desc.get("PublicIpAddress")
        log(f"started {iid}; running at {ip}")
    else:
        die(f"{iid} is {state}; cannot start (wait for it to settle, then retry).")

    if pin is None and kv_reachable():
        pin = pin_for_region(region)
    if pin:
        print(f"\nClient config (fresh IP):\n       curl '{client_url(pin)}'"
              f"                # subscription URL\n       open '{qr_url(pin)}'   # QR page")


def cmd_stop(args) -> None:
    region, _pin = resolve_target(args)
    ec2 = connect_aws(region)
    inst = existing_xray(ec2)
    if not inst:
        die(f"no VM tagged Name={XRAY_NAME_TAG} in {region}")
    iid = inst["InstanceId"]
    state = inst["State"]["Name"]

    if state == "stopped":
        log(f"{iid} is already stopped (nothing to do).")
        return
    if state != "running":
        die(f"{iid} is {state}; cannot stop (wait for it to settle, then retry).")
    if args.dry_run:
        log(f"[dry-run] would stop {iid}.")
        return
    log(f"stopping {iid} ...")
    ec2.stop_instances(InstanceIds=[iid])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[iid])
    log(f"stopped {iid}.")


def cmd_delete(args) -> None:
    region, pin = resolve_target(args)
    ec2 = connect_aws(region)
    inst = existing_xray(ec2)
    if pin is None and kv_reachable():
        pin = pin_for_region(region)
    kv_cleanup = bool(pin and kv_reachable())

    if args.dry_run:
        if inst:
            log(f"[dry-run] would terminate {inst['InstanceId']} "
                f"({inst['State']['Name']}) in {region}")
        else:
            log(f"[dry-run] no VM in {region} to terminate")
        if kv_cleanup:
            log(f"[dry-run] would delete KV {KV_KEY_PREFIX}{pin}")
        return

    actions = []
    if inst:
        actions.append(f"terminate {inst['InstanceId']} ({inst['State']['Name']}) in {region}")
    if kv_cleanup:
        actions.append(f"delete KV profile pin {pin}")
    if not actions:
        log(f"nothing to delete in {region} (no VM, and no KV profile to remove).")
        return
    if not args.yes:
        ans = input("About to " + " and ".join(actions) + ". Proceed? [y/N] ")
        if ans.strip().lower() not in ("y", "yes"):
            die("aborted by user")

    if inst:
        iid = inst["InstanceId"]
        # termination protection may be on; clear it first (best-effort).
        try:
            ec2.modify_instance_attribute(InstanceId=iid,
                                          DisableApiTermination={"Value": False})
        except ClientError as e:
            log(f"note: could not clear termination protection "
                f"({e.response['Error']['Code']}); continuing")
        log(f"terminating {iid} ...")
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[iid])
        log(f"terminated {iid}.")
    else:
        log(f"no VM tagged Name={XRAY_NAME_TAG} in {region} (already gone?).")

    if kv_cleanup:
        try:
            kv_delete_profile(pin)
            log(f"deleted KV {KV_KEY_PREFIX}{pin}")
        except Exception as exc:
            log(f"warning: could not delete KV {KV_KEY_PREFIX}{pin} ({exc})")
    elif not kv_reachable():
        log("KV unreachable — no client profile removed (remove it later if one exists).")


def cmd_export(args) -> None:
    """Dump every KV profile to a JSON object { "<pin>": {profile}, ... }."""
    if not kv_reachable():
        die("export needs Cloudflare KV, which is unreachable.")
    profiles = {}
    for pin in sorted(kv_list_pins()):
        prof = kv_get_profile(pin)
        if prof is not None:
            profiles[pin] = prof
    text = json.dumps(profiles, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n")
        log(f"exported {len(profiles)} profile(s) to {args.out}")
    else:
        print(text)


def cmd_import(args) -> None:
    """Write profiles from a JSON object { "<pin>": {profile}, ... } back to KV
    (upsert). With --prune, also delete KV pins absent from the file."""
    if not kv_reachable():
        die("import needs Cloudflare KV, which is unreachable.")
    try:
        data = json.loads(Path(args.infile).read_text())
    except FileNotFoundError:
        die(f"{args.infile}: no such file")
    except json.JSONDecodeError as e:
        die(f"{args.infile}: invalid JSON ({e})")
    if not isinstance(data, dict):
        die("expected a JSON object mapping PIN -> profile (see `export`).")

    for pin, prof in data.items():
        if not isinstance(prof, dict):
            die(f"pin {pin}: profile must be an object")
        missing = [k for k in REQUIRED_PROFILE_KEYS if k not in prof]
        if missing:
            die(f"pin {pin}: profile is missing required key(s) {missing}")

    current = kv_list_pins()
    incoming = set(data)
    adds = sorted(incoming - current)
    updates = sorted(incoming & current)
    prune = sorted(current - incoming) if args.prune else []

    log(f"{len(adds)} new, {len(updates)} updated"
        + (f", {len(prune)} to prune" if args.prune else ""))
    for p in adds:
        log(f"  + pin {p} ({data[p].get('name', '')})")
    for p in updates:
        log(f"  ~ pin {p} ({data[p].get('name', '')})")
    for p in prune:
        log(f"  - pin {p}")

    if args.dry_run:
        log("[dry-run] no KV writes.")
        return
    if not incoming and not prune:
        log("nothing to import.")
        return
    if not args.yes:
        ans = input(f"Write {len(incoming)} profile(s) to KV"
                    + (f" and delete {len(prune)}" if prune else "") + "? [y/N] ")
        if ans.strip().lower() not in ("y", "yes"):
            die("aborted by user")

    for pin in sorted(incoming):
        kv_put_profile(pin, data[pin])
    for pin in prune:
        kv_delete_profile(pin)
    log(f"done — {len(incoming)} written"
        + (f", {len(prune)} deleted" if prune else "") + ".")


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #
def _add_selector(sp: argparse.ArgumentParser) -> None:
    """Exactly one of --region / --name / --pin. --region needs no KV; the
    others resolve via KV."""
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--region", help="AWS region id or city alias (no KV needed)")
    g.add_argument("--name", help="select by display name (needs KV)")
    g.add_argument("--pin", help="select by PIN (needs KV)")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="xray.py",
        description="Manage Xray servers on AWS. KV is optional: --region works "
                    "without Cloudflare; --name/--pin need KV.")
    sub = p.add_subparsers(dest="op", required=True, metavar="<op>")

    sp = sub.add_parser("new", help="provision a new VM (one per region) + KV profile")
    sp.add_argument("--region", required=True,
                    help="AWS region id, or a city alias: " + ", ".join(CITY_REGIONS))
    sp.add_argument("--name", required=True, help="display name (e.g. US), shown after '#'")
    sp.add_argument("--pin", default=None,
                    help="PIN clients use to select this server (default: random 5-digit)")
    sp.add_argument("--ssh-cidr", default="0.0.0.0/0",
                    help="CIDR allowed to SSH on port 22 (default: 0.0.0.0/0 = anywhere)")
    sp.add_argument("--dry-run", action="store_true", help="checks only; no mutations")
    sp.add_argument("--yes", action="store_true", help="skip the launch confirmation")
    sp.set_defaults(func=cmd_new)

    sp = sub.add_parser("status", help="show the VM's state, IP, and (with KV) its PIN")
    _add_selector(sp)
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("start", help="start the stopped VM")
    _add_selector(sp)
    sp.add_argument("--dry-run", action="store_true", help="checks only; no mutations")
    sp.set_defaults(func=cmd_start)

    sp = sub.add_parser("stop", help="stop the running VM")
    _add_selector(sp)
    sp.add_argument("--dry-run", action="store_true", help="checks only; no mutations")
    sp.set_defaults(func=cmd_stop)

    sp = sub.add_parser("delete", help="terminate the VM and (with KV) delete its profile")
    _add_selector(sp)
    sp.add_argument("--dry-run", action="store_true", help="checks only; no mutations")
    sp.add_argument("--yes", action="store_true", help="skip the confirmation")
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("export", help="dump all KV profiles to JSON (PIN -> profile)")
    sp.add_argument("--out", default=None, help="write to FILE (default: stdout)")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("import", help="write profiles from a JSON file back into KV (upsert)")
    sp.add_argument("--in", dest="infile", required=True,
                    help="JSON file mapping PIN -> profile (from `export`)")
    sp.add_argument("--prune", action="store_true",
                    help="delete KV pins NOT present in the file")
    sp.add_argument("--dry-run", action="store_true", help="show changes; no writes")
    sp.add_argument("--yes", action="store_true", help="skip the confirmation")
    sp.set_defaults(func=cmd_import)

    args = p.parse_args()

    # AWS credentials from .secrets (xray-ops) via python-dotenv.
    if not load_dotenv(SECRETS_FILE):
        log(f"note: {SECRETS_FILE} not loaded; falling back to the default AWS chain")

    args.func(args)


if __name__ == "__main__":
    main()
