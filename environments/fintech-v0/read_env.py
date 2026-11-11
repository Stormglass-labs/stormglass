#!/usr/bin/env python3
# =============================================================
# StormGlass — twin reader v0
# Reads a Terraform plan JSON and reports what StormGlass
# "sees": every resource in the environment, plus the risky
# configurations (flaws) it can detect by inspecting the plan.
#
# This is the first thing the twin builder does: turn a
# machine-readable description of an environment into an
# inventory and a list of weaknesses to reason about.
#
# Usage:  python read_env.py plan.json
# =============================================================

import json
import sys


def load_resources(plan_path):
    """Pull the flat list of planned resources out of the Terraform plan.

    Reads raw bytes and decodes defensively: PowerShell's `>` redirect
    writes UTF-16 with a byte-order mark, while terraform itself and most
    tools write UTF-8. This handles whatever the plan file turns out to be.
    """
    with open(plan_path, "rb") as f:
        raw = f.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):      # UTF-16 BOM (PowerShell)
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":               # UTF-8 BOM
        text = raw.decode("utf-8-sig")
    else:                                          # plain UTF-8
        text = raw.decode("utf-8")
    plan = json.loads(text)
    root = plan.get("planned_values", {}).get("root_module", {})
    return root.get("resources", [])


def inventory(resources):
    """Print every resource StormGlass can see, grouped by type."""
    print("=" * 60)
    print(f"  ENVIRONMENT INVENTORY  ({len(resources)} resources)")
    print("=" * 60)
    by_type = {}
    for r in resources:
        by_type.setdefault(r["type"], []).append(r)
    for rtype in sorted(by_type):
        print(f"\n  {rtype}")
        for r in by_type[rtype]:
            tags = r["values"].get("tags") or {}
            name = tags.get("Name", r["name"])
            print(f"    - {name}")


def find_flaws(resources):
    """Inspect the plan for risky configurations. Returns a list of findings."""
    findings = []

    # Flaw 1: security group allowing SSH (22) from the whole internet
    for r in resources:
        if r["type"] != "aws_security_group":
            continue
        for rule in r["values"].get("ingress", []) or []:
            opens_ssh = rule.get("from_port", 0) <= 22 <= rule.get("to_port", 0)
            from_anywhere = "0.0.0.0/0" in (rule.get("cidr_blocks") or [])
            if opens_ssh and from_anywhere:
                findings.append(
                    f"[SSH-OPEN]  {r['values'].get('name', r['name'])}: "
                    f"port 22 reachable from 0.0.0.0/0 (the whole internet)"
                )

    # Flaw 2: the same IAM instance profile shared across multiple instances
    profile_users = {}
    for r in resources:
        if r["type"] != "aws_instance":
            continue
        prof = r["values"].get("iam_instance_profile")
        if prof:
            tags = r["values"].get("tags") or {}
            profile_users.setdefault(prof, []).append(
                tags.get("Name", r["name"])
            )
    for prof, users in profile_users.items():
        if len(users) > 1:
            findings.append(
                f"[SHARED-ROLE]  profile '{prof}' is attached to "
                f"{len(users)} instances ({', '.join(users)}) — "
                f"owning one grants the permissions of all"
            )

    # Flaw 3: an IAM policy granting a wildcard action on all resources
    for r in resources:
        if r["type"] != "aws_iam_role_policy":
            continue
        try:
            policy = json.loads(r["values"].get("policy", "{}"))
        except (json.JSONDecodeError, TypeError):
            continue
        for stmt in policy.get("Statement", []):
            action = stmt.get("Action", "")
            resource = stmt.get("Resource", "")
            if (isinstance(action, str) and action.endswith(":*")
                    and resource == "*" and stmt.get("Effect") == "Allow"):
                findings.append(
                    f"[WILDCARD-GRANT]  policy '{r['values'].get('name', r['name'])}': "
                    f"allows '{action}' on ALL resources ('*')"
                )

    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python read_env.py plan.json")
        sys.exit(1)

    resources = load_resources(sys.argv[1])
    inventory(resources)

    findings = find_flaws(resources)
    print("\n" + "=" * 60)
    print(f"  FLAWS DETECTED  ({len(findings)})")
    print("=" * 60)
    if not findings:
        print("\n  None found.")
    for f in findings:
        print(f"\n  {f}")
    print()


if __name__ == "__main__":
    main()
