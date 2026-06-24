# myxray

A **Cloudflare Python Worker** that hands an Xray client (e.g. the **Hiddify**
Android app) a ready-to-use connection URL. Given a PIN, it selects a server,
finds (and if needed boots) that server's AWS EC2 VM tagged `Name=xray`, grabs
the public IP, and builds an Xray (VLESS + REALITY) share URL.

It runs on the [Python Workers](https://developers.cloudflare.com/workers/languages/python/)
runtime (Pyodide) and is managed with **`pywrangler`** (the `uv`-first CLI from
the `workers-py` package).

> **Status (2026-06-24):** Worker `xsubs` deployed at
> `https://xsubs.<your-subdomain>.workers.dev` (no custom domain). Per-server profiles
> live in a **Cloudflare KV namespace** (binding `XRAY_KV`), one JSON value per
> `pin:<PIN>` key. No servers are currently provisioned — create one with
> `scripts/xray.py new` (see "Create a new Xray server").

---

## What it does

A request to the Worker:

```
GET https://xsubs.<your-subdomain>.workers.dev/?pin=2580
```

1. **Validate `pin`.** The PIN selects a server profile, fetched from the
   `XRAY_KV` namespace at key `pin:<PIN>` (a single KV read): its AWS region,
   Xray UUID, REALITY public key + short id, and display name. Unknown PINs are
   rejected with `403`.
2. **Resolve the VM.** Using the profile's region, the Worker calls the EC2 API
   to find the instance tagged `Name=xray`:
   - **running** → use its public IP.
   - **stopped** → `StartInstances`, then poll until it is `running` with a
     public IP (up to ~90s).
   - **not found** → abort with `404`.
3. **Build the URL.** The public IP is combined with the profile's Xray
   credentials and the common parameters (`config.SNI`, `config.XRAY_PORT`, …)
   into a `vless://…` share URL.
4. **Return** the result: `mode=url` (default) sends the URL as `text/plain` for
   the Xray client to import; `mode=qr` sends a self-contained HTML page with the
   URL rendered as a scannable QR code (inline SVG, generated server-side).

### Parameters

| Query param | Meaning | Example |
|-------------|---------|---------|
| `pin`       | Client PIN; selects the server profile (region + Xray credentials) | `2580` |
| `mode`      | Output format: `url` (plain text, **default**) or `qr` (HTML page with an embedded, scannable QR code) | `qr` |

### PINs → servers

Each PIN maps to a full server profile (region, UUID, REALITY public key, short
id, name) stored as a JSON value at key `pin:<PIN>` in the `XRAY_KV` namespace,
populated by `scripts/xray.py new`. Keeping profiles in KV (rather than a
committed `servers.py`) keeps the per-server Xray credentials out of the git
repo. (None are provisioned right now.)

> KV is not encrypted-secret storage — values are readable by anyone with
> Cloudflare account access (the AWS keys are still kept as encrypted Worker
> *secrets*). The win here is that `uuid`/`sid` no longer live in source control.

### Responses

| Status | When |
|--------|------|
| `200`  | `mode=url`: plain-text `vless://…` URL · `mode=qr`: HTML page with a QR code (both sent `Cache-Control: no-store`, since the IP changes on VM reboot) |
| `400`  | Missing `pin`, or unknown `mode` |
| `403`  | Unknown `pin` |
| `404`  | No `xray` VM in the profile's region |
| `500`  | Missing AWS credentials / unexpected error |
| `502`  | EC2 API error or VM never became ready |

---

## How it's built

- **No `boto3`.** boto3 needs raw sockets and does not run in a Worker. Instead
  the Worker signs EC2 **Query API** requests with **AWS SigV4** implemented in
  the standard library (`src/sigv4.py`) and sends them via the JavaScript
  `fetch` interop (`src/aws_ec2.py`). XML responses are parsed with
  `xml.etree.ElementTree`.
- **One small runtime dependency** — `segno` (pure Python, dependency-free) for
  the QR page. The core path (EC2 lookup + SigV4) is stdlib + `fetch` only. QR
  codes are generated server-side as an inline SVG, so the share URL (which
  contains the user's UUID) is never sent to a third-party QR service.

```
myxray/
├── pyproject.toml      # deps: segno (runtime), workers-py (dev)
├── wrangler.jsonc      # Worker config (python_workers flag, name, entry)
├── src/
│   ├── entry.py        # WorkerEntrypoint: request handling + orchestration
│   ├── config.py       # common Xray params + share-URL builder
│   ├── aws_ec2.py      # EC2 describe/start over fetch; boot-and-poll logic
│   ├── sigv4.py        # AWS SigV4 request signing (stdlib only)
│   └── render.py       # QR-code HTML page (segno inline SVG) for ?mode=qr
├── scripts/
│   ├── aws_role.sh         # create/verify the xray-ops IAM user + policy
│   ├── xray.py             # manage Xray VMs: new/status/start/stop/delete (PEP 723)
│   └── local_lookup.py     # local EC2-lookup harness (no Workers runtime)
└── CLAUDE.md
```

---

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) installed.
- **Node 22 LTS** (or 20). `pywrangler`/Pyodide require it; **Node 23+ breaks the
  build** with `node: bad option: --experimental-wasm-stack-switching`. Install
  and pin it with Homebrew:
  ```bash
  brew install node@22 && brew link --overwrite node@22
  node --version            # must print v22.x
  ```
- A Cloudflare account (`pywrangler` will prompt you to log in on first deploy).
- AWS IAM credentials able to describe EC2 + VPC and start/stop/terminate/run
  instances (`scripts/aws_role.sh` provisions a least-privilege `xray-ops` user
  with exactly this).

`pywrangler` comes from the `workers-py` dev dependency in `pyproject.toml`, so
you run it through `uv run` — no global install needed. `uv` fetches it on first
use. (To bootstrap a brand-new project you'd use
`uvx --from workers-py pywrangler init`, but this repo is already scaffolded.)

> `pywrangler` is a wrapper around `wrangler`: it uses `uv` to install
> Python-Worker-compatible dependencies and `wrangler` to run/deploy.

---

## Configure before first deploy

1. **KV namespace** — create the namespace that holds the per-server profiles
   and paste its id into `wrangler.jsonc` (the `kv_namespaces` binding `XRAY_KV`):

   ```bash
   uv run pywrangler kv namespace create XRAY_KV   # prints { id = "..." }
   ```

   Then add servers with `scripts/xray.py new` (it writes `pin:<PIN>` keys
   into this namespace — see "Create a new Xray server"). No `PIN_PROFILES` in
   source anymore.
2. **Common Xray params** — set `SNI`, `FINGERPRINT`, `XRAY_PORT` in
   `src/config.py` (shared by every server).
3. **AWS credentials.** Create the `xray-ops` IAM user and a verified access key
   with the helper script (see below), or bring your own. Then store them.

   Keep the creds in a **git-ignored `.secrets`** file (format `KEY=VALUE`):

   ```
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   # AWS_SESSION_TOKEN=...   # only for temporary STS credentials
   ```

   This file is just a local source for the credentials — the deployed Worker's
   real secrets live encrypted **on Cloudflare**, not in any file. Upload them
   once (they persist across every future deploy):

   ```bash
   uv run pywrangler secret bulk .secrets        # uploads every KEY=VALUE
   # or one at a time, interactively:
   uv run pywrangler secret put AWS_ACCESS_KEY_ID
   ```

   `.secrets` is git-ignored; commit `.secrets.example` (placeholders only) as
   documentation. (For an occasional local run, `uv run pywrangler dev
   --env-file .secrets`; without `--env-file`, `pywrangler dev` only auto-loads
   a file literally named `.dev.vars` — wrangler's local-dev convention.)

### Create the IAM user (`scripts/aws_role.sh`)

Creates/updates the least-privilege `xray-ops` IAM user, mints an access key, and
verifies it. Permissions granted:
- **Read**: EC2 describe + VPC lookups (subnets / route-tables / internet-gateways)
  — used to find an internet-facing subnet when provisioning.
- **Manage** (scoped to instances tagged `Name=xray`): start / stop / terminate /
  modify-attribute (e.g. to disable termination protection before deleting).
- **Provision**: `RunInstances`, create/authorize the `xray-sg` security group,
  and tag-on-create. (No key pairs — the SSH key is authorized via cloud-init.)

It then dry-runs Start / Run / Terminate (nothing is actually changed):

```bash
./scripts/aws_role.sh                          # region from your AWS config
USER_NAME=xray-ops REGION=us-west-2 ./scripts/aws_role.sh
```

Requires an AWS CLI identity allowed to manage IAM. Paste the printed key/secret
into `.secrets`, then `secret bulk` it as above.

---

## Deploy

> **Requires Node 22** active (Node 23+ breaks the Pyodide build). Check with
> `node --version`; if it's not v22.x:
> `brew install node@22 && brew link --overwrite node@22`.

First-time deploy:

```bash
# 0. confirm the toolchain
node --version                          # v22.x (or v20.x)

# 1. configure src/config.py + .secrets   (see "Configure before first deploy")

# 2. log in to Cloudflare (one-time, opens a browser)
uv run pywrangler login

# 3. create the KV namespace for profiles, then paste its id into wrangler.jsonc
#    (kv_namespaces -> binding XRAY_KV). One-time.
uv run pywrangler kv namespace create XRAY_KV

# 4. upload AWS secrets to Cloudflare (one-time; persists across deploys)
uv run pywrangler secret bulk .secrets

# 5. deploy — output prints the live URL, e.g. https://xsubs.<your-subdomain>.workers.dev
uv run pywrangler deploy

# 6. provision a server (writes its profile into KV), then verify
uv run scripts/xray.py new --region us-west-2 --name US
curl "https://xsubs.<your-subdomain>.workers.dev/?pin=<printed-pin>"
```

**Redeploy** after any code/config change is just `uv run pywrangler deploy` —
secrets and the workers.dev URL persist, so steps 2–3 are one-time only. Preview
a build without publishing with `uv run pywrangler deploy --dry-run`.

---

## Commands

```bash
# Run locally (http://localhost:8787) with hot reload  (also needs Node 22)
uv run pywrangler dev

# Try it
curl "http://localhost:8787/?pin=2580"

# Deploy to Cloudflare
uv run pywrangler deploy

# Generate type hints for the Workers runtime (optional, for editor support)
uv run pywrangler types

# Tail live logs from the deployed Worker
uv run pywrangler tail
```

After `uv run pywrangler deploy`, the Worker is reachable at
`https://xsubs.<your-subdomain>.workers.dev/?pin=...`.

### Custom domain (optional — currently disabled)

The Worker is served on its **workers.dev URL** (`"workers_dev": true`), so no DNS
is required. If you additionally want a custom hostname like `xsubs.vino9.net`,
uncomment the `routes` block in `wrangler.jsonc` and create the DNS record below.
A route binds the Worker to a hostname via a DNS record in the (Cloudflare-hosted)
`vino9.net` zone:

```jsonc
"routes": [
  { "pattern": "xsubs.vino9.net/*", "zone_name": "vino9.net" }
]
```

**Step 1 — create the proxied DNS record** (Cloudflare dashboard → `vino9.net` →
DNS → Records → *Add record*):

| Field   | Value                                              |
|---------|----------------------------------------------------|
| Type    | `AAAA` (or `A`)                                     |
| Name    | `xsubs`                                             |
| IPv6/IP | `100::` for AAAA (or `192.0.2.1` for A) — a placeholder; the proxy intercepts the request before any origin is reached |
| Proxy   | **Proxied (orange cloud)** — required; DNS-only (grey) will NOT route to the Worker |
| TTL     | Auto                                               |

The record's address is irrelevant because a proxied request bound to a Worker
route is handled by the Worker and never forwarded to that address. Cloudflare
provisions TLS for the hostname automatically.

**Step 2 — deploy** so the route attaches:

```bash
uv run pywrangler deploy
```

It then answers at `https://xsubs.vino9.net/?pin=2580`.

> If the route doesn't take effect, the usual cause is the DNS record being set
> to **DNS-only (grey cloud)** — toggle it to **Proxied**.

---

## Common tasks (runbook)

Step-by-step for the things you'll actually do. All commands run from the repo
root. Deploys need **Node 22** on `PATH` (Node 23+ breaks the Pyodide build):

```bash
node --version            # must be v22.x (or v20.x); if not:
brew install node@22 && brew link --overwrite node@22
```

### Deploy / redeploy after a code or config change

```bash
uv run pywrangler deploy
```

Secrets and routes persist; you only re-run `deploy`. To preview the build
without publishing, add `--dry-run`.

### Change the custom domain / subdomain

1. Edit the `routes` pattern in `wrangler.jsonc`, e.g.
   `{ "pattern": "<new-host>.vino9.net/*", "zone_name": "vino9.net" }`.
2. In the Cloudflare dashboard, add a **Proxied (orange-cloud)** DNS record for
   the new host (`AAAA` → `100::`), per the *Custom domain* section above.
3. `uv run pywrangler deploy` — wrangler attaches the new route and drops the
   old one. Delete the old host's DNS record in the dashboard.

### Manage Xray servers (`scripts/xray.py`)

One tool covers the whole lifecycle, one VM per region (tagged `Name=xray`):

```
uv run scripts/xray.py new    --region <region> --name <Label> [--pin <pin>]
uv run scripts/xray.py status (--region <region> | --name <Label> | --pin <pin>)
uv run scripts/xray.py start  (--region <region> | --name <Label> | --pin <pin>)
uv run scripts/xray.py stop   (--region <region> | --name <Label> | --pin <pin>)
uv run scripts/xray.py delete (--region <region> | --name <Label> | --pin <pin>) [--yes]
```

**AWS is the source of truth; Cloudflare KV is an optional convenience layer.**
The VM is always found by its `Name=xray` tag, so **`--region` works without
KV**. `--name` / `--pin` are KV-backed aliases for a region (KV is the only place
that maps them), so they **require KV** — if KV is unreachable the command tells
you to select with `--region` instead. AWS creds come from `.secrets` (xray-ops)
via python-dotenv; KV access reuses your `pywrangler login`. All ops accept
`--dry-run` except `status` (which is read-only); `new`/`delete` accept `--yes`.

> The script prints ready-to-run `curl` commands using your Worker URL. Since
> this is a public repo, the URL is **not** hard-coded — set it once per shell so
> the printed commands are runnable:
> ```bash
> export XRAY_WORKER_URL="https://xsubs.<your-subdomain>.workers.dev"
> ```
> Without it, the commands show the `<your-subdomain>` placeholder (everything
> else still works).

#### `new` — provision a server

```bash
uv run scripts/xray.py new --region us-west-2      --name US
uv run scripts/xray.py new --region tokyo          --name Tokyo --pin 1470
uv run scripts/xray.py new --region eu-central-1   --name EU --dry-run   # preview
# verify (note the printed PIN; allow ~1-2 min for Xray to finish installing)
curl "https://xsubs.<your-subdomain>.workers.dev/?pin=<pin>"
```

What it does (no SSH needed for setup):
- Aborts if a `Name=xray` VM already exists in that region (use `status` /
  `start` / `delete` for an existing one).
- Picks the **first existing EC2 key pair** in the region for SSH access (aborts
  if none — create one, and keep its `.pem`, first).
- Finds an internet-facing subnet; creates the **`xray-sg`** security group
  (443 + 22 from anywhere; restrict SSH with `--ssh-cidr`).
- Generates the UUID + REALITY x25519 keypair + short id **locally**, and launches
  a **Debian 13 arm64 `t4g.micro`** whose cloud-init installs Xray, writes
  `config.json` (logs to `/var/log/xray`), and starts the service.
- If KV is reachable: enforces a **unique display name**, then writes the client
  profile (region / uuid / pbk / sid / name) to `pin:<PIN>`. If KV is down it
  still provisions the VM and prints the profile + the `wrangler kv key put`
  command to add it later.

`--pin` is optional (a random 5-digit PIN is generated). Server template /
instance type / SNI etc. are constants near the top of the script — tune
`render_xray_config()` to change the config (keep SNI/PORT/FLOW in sync with
`src/config.py`).

#### `status` / `start` / `stop` / `delete` — manage an existing server

```bash
uv run scripts/xray.py status --region us-west-2     # state + IP (+ PIN if KV up)
uv run scripts/xray.py status --pin 1470             # by PIN (needs KV)
uv run scripts/xray.py start  --name Tokyo           # boot a stopped VM (needs KV)
uv run scripts/xray.py stop   --region us-west-2     # stop a running VM
uv run scripts/xray.py delete --region us-west-2 --yes   # terminate VM + delete KV key
```

- `status` reports the VM's state and public IP; with KV up it also prints the
  PIN and the ready-to-use client URL.
- `start` boots a stopped VM and waits for the (new) public IP. The Worker
  resolves the IP live on every request, so existing client URLs keep working.
- `stop` stops a running VM (saves cost; the IP is released).
- `delete` disables termination protection, terminates the VM, and — when KV is
  reachable — deletes its `pin:<PIN>` key (it derives the PIN from the region if
  you selected by `--region`). This replaces the manual EC2/KV teardown.

#### `export` / `import` — bulk edit profiles as a JSON file

Dump every profile to a single JSON file, edit it by hand, and push it back.
Both need KV (they only touch KV — no AWS). The file is a JSON object keyed by
bare PIN (`export` sorts keys for stable diffs):

```bash
# export all profiles (default: stdout; --out writes a file)
uv run scripts/xray.py export --out servers.json

# ... edit servers.json by hand ...

uv run scripts/xray.py import --in servers.json --dry-run   # preview the changes
uv run scripts/xray.py import --in servers.json             # upsert (writes + confirm)
```

`servers.json` looks like:

```json
{
  "2580": {"region":"us-west-2","name":"US","uuid":"<uuid>","pbk":"<pbk>","sid":"<sid>"},
  "1470": {"region":"ap-northeast-1","name":"Tokyo","uuid":"<uuid>","pbk":"<pbk>","sid":"<sid>"}
}
```

- `import` is an **upsert**: each PIN in the file is written (new ones added,
  existing ones overwritten). PINs already in KV but **absent from the file are
  left alone** unless you pass `--prune` (which deletes them). It validates that
  every profile has `region`, `name`, `uuid`, `pbk`, `sid` before writing
  anything, and `--dry-run` shows the add/update/prune plan without touching KV.
- `servers.json` contains per-server UUIDs — treat it like a secret (don't
  commit it; it's covered by `.secrets`/`*.pem`-style hygiene, add it to
  `.gitignore` if you keep it around).

**Adding a 2nd user to an existing server.** A "user" is an Xray client UUID.
To give a server a second user with its own PIN:

1. Pick a new UUID (e.g. `python3 -c 'import uuid; print(uuid.uuid4())'`).
2. **On the VM**, add that UUID to the `clients` array in
   `/usr/local/etc/xray/config.json` (same `flow`), then
   `sudo systemctl restart xray`. (SSH in with the region's EC2 key pair.)
3. **In KV**, add a new entry via export/import: copy the server's existing
   profile to a new PIN, keeping the same `region`/`pbk`/`sid`, and set the new
   `uuid` (and a distinct `name` — names must be unique):

   ```jsonc
   "73218": {"region":"us-west-2","name":"US-alice","uuid":"<new-uuid>","pbk":"<same-pbk>","sid":"<same-sid>"}
   ```

   Then `uv run scripts/xray.py import --in servers.json`. Both PINs now point at
   the same VM, each handing its user a distinct UUID.

> Note: `export`/`import` only manage the KV side (what the Worker hands clients).
> The server's `config.json` (which UUIDs it actually accepts) is edited
> separately over SSH, as in step 2 — they are not kept in sync automatically.

#### Manual KV alternative (no script)

```bash
uv run pywrangler kv key put --binding XRAY_KV --remote pin:2580 \
  '{"region":"us-west-2","name":"US","uuid":"...","pbk":"...","sid":"..."}'
# inspect / remove:
uv run pywrangler kv key list --binding XRAY_KV --remote
uv run pywrangler kv key get  --binding XRAY_KV --remote pin:2580
uv run pywrangler kv key delete --binding XRAY_KV --remote pin:2580
```

### Change the common Xray params (sni / fingerprint / port)

Edit `SNI`, `FINGERPRINT`, or `XRAY_PORT` in `src/config.py` (the per-server
`pbk` / `sid` / `name` live in the `XRAY_KV` namespace). Then `uv run pywrangler
deploy`. The generated URL updates immediately.

### Rotate AWS credentials

```bash
./scripts/aws_role.sh                              # mints + verifies a new key
# paste the printed key/secret into .secrets, then:
uv run pywrangler secret bulk .secrets             # push to Cloudflare
# then delete the OLD key so only the new one is live:
aws iam list-access-keys --user-name xray-ops
aws iam delete-access-key --user-name xray-ops --access-key-id <OLD_ID>
```

(No redeploy needed — secrets update independently of the Worker code.)

### Inspect / debug a live request

```bash
uv run pywrangler tail                                      # stream live logs + errors
curl "https://xsubs.<your-subdomain>.workers.dev/?pin=<pin>"            # exercise it
```

### Verify the AWS lookup locally (without deploying)

Runs the real signing code against AWS over `urllib` (needs Python ≥3.10):

```bash
python3 scripts/local_lookup.py                     # us-west-2, tag Name=xray
REGION=ap-northeast-1 python3 scripts/local_lookup.py
```

### Roll back to a previous version

```bash
uv run pywrangler deployments list                  # find the prior Version ID
uv run pywrangler rollback [<version-id>]
```

### Tear down

```bash
# 1. delete each server (terminates the VM + removes its KV profile). Repeat per
#    region, or select by --name / --pin. See "Manage Xray servers".
uv run scripts/xray.py delete --region us-west-2 --yes

# 2. remove the Worker + KV namespace + IAM user
uv run pywrangler delete                            # remove the Worker + routes
uv run pywrangler kv namespace list                 # find the XRAY_KV id
uv run pywrangler kv namespace delete --namespace-id <ID>   # remove the profiles
aws iam delete-access-key --user-name xray-ops --access-key-id <ID>
aws iam delete-user-policy --user-name xray-ops --policy-name xray-ops-ec2
aws iam delete-user --user-name xray-ops
```

If you enabled the optional custom domain, also delete its DNS record in the
Cloudflare dashboard (not needed for the workers.dev setup).

---

## Using it from Hiddify (or another Xray client)

The Worker returns a single `vless://…` line. Either:

- Paste the URL printed by `curl`/the browser directly into the client, **or**
- Point the client's *subscription* URL at the Worker endpoint
  (`https://xsubs.<subdomain>.workers.dev/?pin=2580`) so it re-fetches a fresh IP
  each time the VM is rebooted, **or**
- Open `…/?pin=2580&mode=qr` in a browser to get a scannable QR-code page and
  import it into the phone app with the camera.
