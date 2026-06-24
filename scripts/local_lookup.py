#!/usr/bin/env python3
"""Local check of the EC2 VM lookup WITHOUT the Cloudflare Workers runtime.

This reuses the EXACT signing code the Worker uses (src/sigv4.py) and mirrors the
EC2 Query API call + XML parsing from src/aws_ec2.py, but swaps the Worker's JS
`fetch` transport for urllib so it runs on a normal Python interpreter.

Credentials are read from the git-ignored .secrets file.

Usage:
    python3 scripts/local_lookup.py                 # us-west-2, tag Name=xray
    REGION=ap-northeast-1 XRAY_TAG=xray python3 scripts/local_lookup.py
"""
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from sigv4 import sign_request  # the real Worker signing code

API_VERSION = "2016-11-15"


def load_secrets(path):
    creds = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            creds[k.strip()] = v.strip()
    return creds


def ec2_call(region, creds, params):
    host = f"ec2.{region}.amazonaws.com"
    url = f"https://{host}/"
    body = urlencode(params)
    headers = sign_request(
        method="POST",
        host=host,
        region=region,
        service="ec2",
        body=body,
        access_key=creds["AWS_ACCESS_KEY_ID"],
        secret_key=creds["AWS_SECRET_ACCESS_KEY"],
        session_token=creds.get("AWS_SESSION_TOKEN"),
    )
    req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    region = os.environ.get("REGION", "us-west-2")
    name = os.environ.get("XRAY_TAG", "xray")
    creds = load_secrets(os.path.join(ROOT, ".secrets"))

    print(f"==> region={region}  tag:Name={name}  key={creds['AWS_ACCESS_KEY_ID'][:8]}...")
    status, text = ec2_call(
        region,
        creds,
        {
            "Action": "DescribeInstances",
            "Version": API_VERSION,
            "Filter.1.Name": "tag:Name",
            "Filter.1.Value.1": name,
        },
    )
    print(f"==> HTTP {status}")
    if status != 200:
        print(text[:800])
        sys.exit(1)

    root = ET.fromstring(text)
    inst = root.find(".//{*}instancesSet/{*}item")
    if inst is None:
        print("==> RESULT: no VM found with that tag (Worker would return 404)")
        sys.exit(2)

    def t(path):
        el = inst.find(path)
        return el.text if el is not None else None

    print("==> RESULT: VM found")
    print(f"    instanceId : {t('{*}instanceId')}")
    print(f"    state      : {t('{*}instanceState/{*}name')}")
    print(f"    publicIp   : {t('{*}ipAddress')}")


if __name__ == "__main__":
    main()
