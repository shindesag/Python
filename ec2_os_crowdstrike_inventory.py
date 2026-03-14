#!/usr/bin/env python3
"""EC2 OS and CrowdStrike inventory collector.

Features
--------
1. Authenticates to AWS using boto3 default credential chain (or optional profile).
2. Accepts a list of EC2 instance IDs.
3. Collects private IP, AMI ID, and AMI details.
4. Identifies whether each instance is Linux or Windows.
5. For Linux, tries to detect distribution/version.
6. For Windows, tries to detect Windows version.
7. Queries installed CrowdStrike Falcon Sensor version through AWS Systems Manager.

Requirements
------------
- boto3 installed
- IAM permissions for:
  - ec2:DescribeInstances
  - ec2:DescribeImages
  - ssm:SendCommand
  - ssm:GetCommandInvocation
- SSM Agent online on target instances for OS/version/CrowdStrike detection.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional

import boto3
from botocore.exceptions import ClientError


@dataclass
class InstanceInventory:
    instance_id: str
    private_ip: Optional[str] = None
    ami_id: Optional[str] = None
    ami_name: Optional[str] = None
    ami_platform_details: Optional[str] = None
    os_family: str = "Unknown"
    os_version: str = "Unknown"
    crowdstrike_version: str = "Unknown"
    notes: str = ""


def chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def create_clients(region: str, profile: Optional[str]):
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    return session.client("ec2"), session.client("ssm")


def get_instances(ec2_client, instance_ids: List[str]) -> Dict[str, dict]:
    found: Dict[str, dict] = {}
    for ids in chunked(instance_ids, 100):
        response = ec2_client.describe_instances(InstanceIds=ids)
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                found[instance["InstanceId"]] = instance
    return found


def get_ami_details(ec2_client, ami_ids: List[str]) -> Dict[str, dict]:
    ami_ids = sorted({ami for ami in ami_ids if ami})
    if not ami_ids:
        return {}
    details: Dict[str, dict] = {}
    for ids in chunked(ami_ids, 100):
        response = ec2_client.describe_images(ImageIds=ids)
        for image in response.get("Images", []):
            details[image["ImageId"]] = image
    return details


def infer_os_family(instance: dict, ami: Optional[dict]) -> str:
    if instance.get("Platform") == "windows":
        return "Windows"

    platform_details = (instance.get("PlatformDetails") or "").lower()
    if "windows" in platform_details:
        return "Windows"
    if any(token in platform_details for token in ["linux", "unix", "red hat", "ubuntu", "suse", "debian", "amzn"]):
        return "Linux"

    if ami:
        ami_pd = (ami.get("PlatformDetails") or "").lower()
        if "windows" in ami_pd:
            return "Windows"
        if any(token in ami_pd for token in ["linux", "unix", "red hat", "ubuntu", "suse", "debian", "amzn"]):
            return "Linux"

        name = (ami.get("Name") or "").lower()
        if "windows" in name:
            return "Windows"
        if any(token in name for token in ["linux", "ubuntu", "rhel", "redhat", "debian", "suse", "centos", "amzn"]):
            return "Linux"

    return "Unknown"


def wait_for_ssm(ssm_client, command_id: str, instance_id: str, timeout: int = 90) -> dict:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            invocation = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            last_error = str(exc)
            time.sleep(2)
            continue

        status = invocation.get("Status")
        if status in {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}:
            return invocation
        time.sleep(2)

    return {"Status": "TimedOut", "StandardErrorContent": last_error or "SSM invocation timeout"}


def run_ssm_detection(ssm_client, instance_id: str, os_family: str) -> Dict[str, str]:
    """Return {'os_version': str, 'crowdstrike_version': str, 'notes': str}."""
    if os_family == "Linux":
        document = "AWS-RunShellScript"
        commands = [
            "set -e",
            "OS_VER='Unknown'",
            "if [ -f /etc/os-release ]; then",
            "  . /etc/os-release",
            "  OS_VER=\"${PRETTY_NAME:-$NAME $VERSION}\"",
            "else",
            "  OS_VER=$(uname -srmo 2>/dev/null || echo Unknown)",
            "fi",
            "CS_VER='Not Installed'",
            "if command -v falconctl >/dev/null 2>&1; then",
            "  CS_VER=$(falconctl -g --version 2>/dev/null | awk -F'= ' '/version/{print $2}' | head -n1)",
            "fi",
            "if [ -z \"$CS_VER\" ] || [ \"$CS_VER\" = 'Not Installed' ]; then",
            "  if rpm -q falcon-sensor >/dev/null 2>&1; then",
            "    CS_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' falcon-sensor 2>/dev/null)",
            "  elif dpkg -s falcon-sensor >/dev/null 2>&1; then",
            "    CS_VER=$(dpkg -s falcon-sensor | awk -F': ' '/^Version:/{print $2}')",
            "  fi",
            "fi",
            "echo '{\"os_version\":'\"\"\"${OS_VER//\"/\\\"}\"\"\"',\"crowdstrike_version\":'\"\"\"${CS_VER:-Unknown}\"\"\"'}'",
        ]
    elif os_family == "Windows":
        document = "AWS-RunPowerShellScript"
        commands = [
            "$os = (Get-CimInstance Win32_OperatingSystem).Caption",
            "$cs = 'Not Installed'",
            "$falcon = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\CrowdStrike\\Sensor' -ErrorAction SilentlyContinue",
            "if ($falcon -and $falcon.Version) { $cs = $falcon.Version }",
            "if ($cs -eq 'Not Installed') {",
            "  $pkg = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue |",
            "    Where-Object { $_.DisplayName -match 'CrowdStrike|Falcon Sensor' } | Select-Object -First 1",
            "  if ($pkg -and $pkg.DisplayVersion) { $cs = $pkg.DisplayVersion }",
            "}",
            "$out = @{ os_version = $os; crowdstrike_version = $cs } | ConvertTo-Json -Compress",
            "Write-Output $out",
        ]
    else:
        return {"os_version": "Unknown", "crowdstrike_version": "Unknown", "notes": "OS family unknown, skipped SSM checks"}

    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName=document,
            Parameters={"commands": commands},
            CloudWatchOutputConfig={"CloudWatchOutputEnabled": False},
        )
    except ClientError as exc:
        return {
            "os_version": "Unknown",
            "crowdstrike_version": "Unknown",
            "notes": f"Failed to send SSM command: {exc}",
        }

    command_id = response["Command"]["CommandId"]
    invocation = wait_for_ssm(ssm_client, command_id, instance_id)
    if invocation.get("Status") != "Success":
        return {
            "os_version": "Unknown",
            "crowdstrike_version": "Unknown",
            "notes": f"SSM command status: {invocation.get('Status')} - {invocation.get('StandardErrorContent', '').strip()}",
        }

    stdout = (invocation.get("StandardOutputContent") or "").strip().splitlines()
    if not stdout:
        return {"os_version": "Unknown", "crowdstrike_version": "Unknown", "notes": "No output returned from SSM"}

    raw = stdout[-1].strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "os_version": "Unknown",
            "crowdstrike_version": "Unknown",
            "notes": f"Could not parse SSM JSON output: {raw[:200]}",
        }

    return {
        "os_version": parsed.get("os_version", "Unknown") or "Unknown",
        "crowdstrike_version": parsed.get("crowdstrike_version", "Unknown") or "Unknown",
        "notes": "",
    }


def build_inventory(region: str, instance_ids: List[str], profile: Optional[str] = None) -> List[InstanceInventory]:
    ec2_client, ssm_client = create_clients(region=region, profile=profile)

    instances = get_instances(ec2_client, instance_ids)
    ami_lookup = get_ami_details(
        ec2_client,
        [inst.get("ImageId") for inst in instances.values() if inst.get("ImageId")],
    )

    output: List[InstanceInventory] = []

    for instance_id in instance_ids:
        instance = instances.get(instance_id)
        if not instance:
            output.append(
                InstanceInventory(
                    instance_id=instance_id,
                    notes="Instance not found (or no permission)",
                )
            )
            continue

        ami_id = instance.get("ImageId")
        ami = ami_lookup.get(ami_id) if ami_id else None

        record = InstanceInventory(
            instance_id=instance_id,
            private_ip=instance.get("PrivateIpAddress"),
            ami_id=ami_id,
            ami_name=ami.get("Name") if ami else None,
            ami_platform_details=ami.get("PlatformDetails") if ami else None,
            os_family=infer_os_family(instance, ami),
        )

        detection = run_ssm_detection(ssm_client, instance_id, record.os_family)
        record.os_version = detection["os_version"]
        record.crowdstrike_version = detection["crowdstrike_version"]
        record.notes = detection["notes"]
        output.append(record)

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect EC2 OS and CrowdStrike details for instance IDs.")
    parser.add_argument("--region", required=True, help="AWS region, e.g. us-east-1")
    parser.add_argument(
        "--instance-ids",
        nargs="+",
        required=True,
        help="One or more EC2 instance IDs (space-separated)",
    )
    parser.add_argument("--profile", default=None, help="Optional AWS CLI profile name")
    parser.add_argument(
        "--output",
        choices=["json", "table"],
        default="json",
        help="Output format",
    )
    return parser.parse_args()


def print_table(records: List[InstanceInventory]) -> None:
    headers = [
        "InstanceId",
        "PrivateIP",
        "AMI",
        "AMIPlatform",
        "OSFamily",
        "OSVersion",
        "CrowdStrikeVersion",
        "Notes",
    ]
    rows = [
        [
            r.instance_id,
            r.private_ip or "",
            r.ami_id or "",
            r.ami_platform_details or "",
            r.os_family,
            r.os_version,
            r.crowdstrike_version,
            r.notes,
        ]
        for r in records
    ]

    widths = [len(h) for h in headers]
    for row in rows:
        for idx, col in enumerate(row):
            widths[idx] = max(widths[idx], len(str(col)))

    def fmt(values):
        return " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(values))

    print(fmt(headers))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))


def main() -> None:
    args = parse_args()
    records = build_inventory(region=args.region, instance_ids=args.instance_ids, profile=args.profile)

    if args.output == "json":
        print(json.dumps([asdict(r) for r in records], indent=2))
    else:
        print_table(records)


if __name__ == "__main__":
    main()
