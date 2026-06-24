#!/usr/bin/env bash
#
# Create (or update) the IAM user `xray-ops` used to operate the Xray EC2 VM(s)
# tagged Name=xray: look them up, start/stop them, and provision or terminate
# them. It also grants the read-only VPC lookups (subnets / route-tables /
# internet-gateways) needed to find an internet-facing subnet when provisioning a
# new VM.
#
# It is idempotent: re-running updates the inline policy and mints a fresh access
# key. After creating the user it VERIFIES the new key by exercising the read
# permissions (DescribeInstances + VPC lookup) and dry-running Start / Run /
# Terminate — nothing is actually launched, stopped, or destroyed.
#
# Requirements: the AWS CLI must be configured with an identity allowed to manage
# IAM (create users, put policies, create access keys).
#
# Usage:
#   ./scripts/aws_role.sh                 # user xray-ops, region from AWS config
#   USER_NAME=xray-ops REGION=us-west-2 ./scripts/aws_role.sh
#
set -euo pipefail

USER_NAME="${USER_NAME:-xray-ops}"
REGION="${REGION:-$(aws configure get region 2>/dev/null || echo us-west-2)}"
XRAY_TAG="${XRAY_TAG:-xray}"   # the Name tag value of the VM the Worker manages

echo "==> Target IAM user : ${USER_NAME}"
echo "==> Verify region   : ${REGION}"
echo "==> VM Name tag     : ${XRAY_TAG}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
echo "==> AWS account     : ${ACCOUNT_ID}"
echo

# --------------------------------------------------------------------------- #
# 1. Create the user (idempotent)                                             #
# --------------------------------------------------------------------------- #
if aws iam get-user --user-name "${USER_NAME}" >/dev/null 2>&1; then
  echo "==> User ${USER_NAME} already exists — reusing."
else
  echo "==> Creating user ${USER_NAME} ..."
  aws iam create-user \
    --user-name "${USER_NAME}" \
    --tags Key=app,Value=myxray Key=managed-by,Value=aws_role.sh \
    >/dev/null
  echo "    created."
fi

# --------------------------------------------------------------------------- #
# 2. Attach the least-privilege inline policy                                 #
# --------------------------------------------------------------------------- #
# Least-privilege policy:
#   * Read/Describe (incl. VPC/subnet/route-table/IGW lookups) — Describe actions
#     don't support resource scoping, so Resource must be "*".
#   * Start/Stop/Terminate — scoped to instances tagged Name=<XRAY_TAG>.
#   * RunInstances — to provision a new VM (it needs a broad set of resource
#     types: instance, subnet, NIC, security-group, volume, key-pair, image, …).
#   * Create/authorize a security group (sg-xray) for a fresh Xray host via
#     scripts/xray.py. Key pairs are reused (existing), not created.
#   * CreateTags — only at create time (Condition ec2:CreateAction), so the new
#     VM / SG can be tagged.
# Note: RunInstances itself is not tag-restricted (enforcing aws:RequestTag across
# all of its resource types is brittle). Start/Stop/Terminate being tag-scoped is
# the real guard — this user can only stop/kill instances tagged Name=<XRAY_TAG>.
POLICY_NAME="xray-ops-ec2"
POLICY_JSON="$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadEc2AndVpc",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeImages",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ManageXrayInstances",
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:ModifyInstanceAttribute"
      ],
      "Resource": "arn:aws:ec2:*:${ACCOUNT_ID}:instance/*",
      "Condition": {
        "StringEquals": { "aws:ResourceTag/Name": "${XRAY_TAG}" }
      }
    },
    {
      "Sid": "LaunchInstances",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": [
        "arn:aws:ec2:*:${ACCOUNT_ID}:instance/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:network-interface/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:subnet/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:security-group/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:volume/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:key-pair/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:placement-group/*",
        "arn:aws:ec2:*::image/*",
        "arn:aws:ec2:*::snapshot/*"
      ]
    },
    {
      "Sid": "ManageXraySecurityGroup",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": [
        "arn:aws:ec2:*:${ACCOUNT_ID}:security-group/*",
        "arn:aws:ec2:*:${ACCOUNT_ID}:vpc/*"
      ]
    },
    {
      "Sid": "TagOnCreate",
      "Effect": "Allow",
      "Action": "ec2:CreateTags",
      "Resource": "arn:aws:ec2:*:${ACCOUNT_ID}:*/*",
      "Condition": {
        "StringEquals": {
          "ec2:CreateAction": [ "RunInstances", "CreateSecurityGroup" ]
        }
      }
    }
  ]
}
JSON
)"

echo "==> Putting inline policy ${POLICY_NAME} ..."
aws iam put-user-policy \
  --user-name "${USER_NAME}" \
  --policy-name "${POLICY_NAME}" \
  --policy-document "${POLICY_JSON}"
echo "    policy applied."
echo

# --------------------------------------------------------------------------- #
# 3. Mint an access key (handle the 2-key IAM limit)                          #
# --------------------------------------------------------------------------- #
EXISTING_KEYS="$(aws iam list-access-keys --user-name "${USER_NAME}" \
  --query 'length(AccessKeyMetadata)' --output text 2>/dev/null || echo 0)"

if [ "${EXISTING_KEYS}" -ge 2 ]; then
  echo "!!! User ${USER_NAME} already has 2 access keys (IAM max)."
  echo "    Delete an unused one, then re-run:"
  aws iam list-access-keys --user-name "${USER_NAME}" \
    --query 'AccessKeyMetadata[].{Key:AccessKeyId,Status:Status,Created:CreateDate}' \
    --output table
  echo "    aws iam delete-access-key --user-name ${USER_NAME} --access-key-id <id>"
  exit 1
fi

echo "==> Creating a new access key ..."
KEY_TSV="$(aws iam create-access-key --user-name "${USER_NAME}" \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)"
ACCESS_KEY_ID="$(printf '%s' "${KEY_TSV}" | cut -f1)"
SECRET_ACCESS_KEY="$(printf '%s' "${KEY_TSV}" | cut -f2)"
echo "    AccessKeyId: ${ACCESS_KEY_ID}"
echo

# Run the AWS CLI as the freshly-created key, in a clean environment so it never
# picks up the caller's credentials/profile.
awsnew() {
  env -i PATH="${PATH}" HOME="${HOME}" \
    AWS_ACCESS_KEY_ID="${ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${SECRET_ACCESS_KEY}" \
    AWS_DEFAULT_REGION="${REGION}" \
    aws "$@"
}

# --------------------------------------------------------------------------- #
# 4. Verify the key is usable                                                 #
# --------------------------------------------------------------------------- #
# New IAM keys are eventually consistent — retry a few times for propagation.
echo "==> Verifying ec2:DescribeInstances with the new key (region ${REGION}) ..."
DESCRIBE_OK=0
for attempt in 1 2 3 4 5 6; do
  if OUT="$(awsnew ec2 describe-instances \
        --filters "Name=tag:Name,Values=${XRAY_TAG}" \
        --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,IP:PublicIpAddress}' \
        --output json 2>/tmp/xray_verify_err)"; then
    DESCRIBE_OK=1
    break
  fi
  echo "    attempt ${attempt}: not ready yet (key propagating), retrying in 5s ..."
  sleep 5
done

if [ "${DESCRIBE_OK}" -ne 1 ]; then
  echo "!!! DescribeInstances failed with the new key:"
  cat /tmp/xray_verify_err
  exit 1
fi
echo "    DescribeInstances OK. Instances tagged Name=${XRAY_TAG} in ${REGION}:"
printf '%s\n' "${OUT}"
echo

# If an xray VM exists, dry-run StartInstances to confirm that permission too.
XRAY_ID="$(printf '%s' "${OUT}" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["Id"] if d else "")' 2>/dev/null || echo "")"
if [ -n "${XRAY_ID}" ]; then
  echo "==> Verifying ec2:StartInstances (dry run) on ${XRAY_ID} ..."
  set +e
  START_OUT="$(awsnew ec2 start-instances --instance-ids "${XRAY_ID}" --dry-run 2>&1)"
  set -e
  if printf '%s' "${START_OUT}" | grep -q "DryRunOperation"; then
    echo "    StartInstances OK (authorized; dry run did not actually start it)."
  else
    echo "!!! StartInstances NOT authorized:"
    printf '%s\n' "${START_OUT}"
    exit 1
  fi
else
  echo "==> No VM tagged Name=${XRAY_TAG} found in ${REGION};"
  echo "    skipping StartInstances dry-run (DescribeInstances permission already verified)."
fi
echo

# --------------------------------------------------------------------------- #
# 5. Verify VPC lookup + provisioning / termination permissions               #
# --------------------------------------------------------------------------- #
echo "==> Verifying VPC lookup (finding internet-facing subnets) in ${REGION} ..."
set +e
RTB_JSON="$(awsnew ec2 describe-route-tables --output json 2>/tmp/xray_verify_err)"; RTB_RC=$?
SUBNET_JSON="$(awsnew ec2 describe-subnets --output json 2>/tmp/xray_verify_err2)"; SUB_RC=$?
set -e
if [ "${RTB_RC}" -ne 0 ] || [ "${SUB_RC}" -ne 0 ]; then
  echo "!!! VPC describe calls failed:"; cat /tmp/xray_verify_err /tmp/xray_verify_err2 2>/dev/null
  exit 1
fi

# A subnet is "internet-facing" if its route table has a 0.0.0.0/0 route to an
# internet gateway. Subnets with no explicit association use the VPC main table.
PUBLIC_SUBNETS="$(python3 - "${RTB_JSON}" "${SUBNET_JSON}" <<'PY'
import sys, json
rtbs = json.loads(sys.argv[1]).get("RouteTables", [])
subnets = json.loads(sys.argv[2]).get("Subnets", [])

def is_public(rt):
    return any(r.get("DestinationCidrBlock") == "0.0.0.0/0"
              and str(r.get("GatewayId", "")).startswith("igw-")
              for r in rt.get("Routes", []))

explicit, public, main_public_vpcs = set(), set(), set()
for rt in rtbs:
    pub = is_public(rt)
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

by_id = {s["SubnetId"]: s for s in subnets}
for sid in sorted(public):
    s = by_id.get(sid, {})
    print(f'{sid}\t{s.get("AvailabilityZone","?")}\t{s.get("VpcId","?")}'
          f'\tauto_public_ip={s.get("MapPublicIpOnLaunch", False)}')
PY
)"

if [ -n "${PUBLIC_SUBNETS}" ]; then
  echo "    internet-facing subnet(s)  [subnet / AZ / vpc / auto-assign-public-ip]:"
  printf '%s\n' "${PUBLIC_SUBNETS}" | sed 's/^/      /'
  FIRST_SUBNET="$(printf '%s\n' "${PUBLIC_SUBNETS}" | head -1 | cut -f1)"
else
  echo "    (no internet-facing subnet found in ${REGION})"
  FIRST_SUBNET=""
fi
echo

echo "==> Verifying ec2:RunInstances (dry run) ..."
AMI_ID="$(awsnew ec2 describe-images --owners amazon \
  --filters 'Name=name,Values=al2023-ami-*-x86_64' 'Name=state,Values=available' \
  --query 'reverse(sort_by(Images,&CreationDate))[0].ImageId' --output text 2>/dev/null || echo None)"
if [ -n "${FIRST_SUBNET}" ] && [ -n "${AMI_ID}" ] && [ "${AMI_ID}" != "None" ]; then
  set +e
  RUN_OUT="$(awsnew ec2 run-instances --image-id "${AMI_ID}" --instance-type t3.micro \
      --subnet-id "${FIRST_SUBNET}" \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${XRAY_TAG}}]" \
      --dry-run 2>&1)"
  set -e
  if printf '%s' "${RUN_OUT}" | grep -q "DryRunOperation"; then
    echo "    RunInstances OK (authorized; nothing was launched). ami=${AMI_ID} subnet=${FIRST_SUBNET}"
  else
    echo "    WARNING: RunInstances dry-run did not confirm authorization:"
    printf '%s\n' "${RUN_OUT}" | sed 's/^/      /'
  fi
else
  echo "    skipped (need an internet-facing subnet and an AMI; none resolved)."
fi
echo

if [ -n "${XRAY_ID}" ]; then
  echo "==> Verifying ec2:TerminateInstances (dry run) on ${XRAY_ID} ..."
  set +e
  TERM_OUT="$(awsnew ec2 terminate-instances --instance-ids "${XRAY_ID}" --dry-run 2>&1)"
  set -e
  if printf '%s' "${TERM_OUT}" | grep -q "DryRunOperation"; then
    echo "    TerminateInstances OK (authorized; nothing was terminated)."
  else
    echo "    WARNING: TerminateInstances dry-run did not confirm authorization:"
    printf '%s\n' "${TERM_OUT}" | sed 's/^/      /'
  fi
fi
echo

# --------------------------------------------------------------------------- #
# 6. Print next steps                                                         #
# --------------------------------------------------------------------------- #
cat <<EOF
============================================================================
SUCCESS — ${USER_NAME} is created and the access key is verified usable.

Store these as Worker secrets (do NOT commit them):

  uv run pywrangler secret put AWS_ACCESS_KEY_ID
      ${ACCESS_KEY_ID}
  uv run pywrangler secret put AWS_SECRET_ACCESS_KEY
      ${SECRET_ACCESS_KEY}

For local dev, put them in the git-ignored .secrets file instead:

  AWS_ACCESS_KEY_ID=${ACCESS_KEY_ID}
  AWS_SECRET_ACCESS_KEY=${SECRET_ACCESS_KEY}

The SecretAccessKey is shown ONLY this once. If you lose it, re-run this
script to mint a new key (and delete the old one).
============================================================================
EOF
