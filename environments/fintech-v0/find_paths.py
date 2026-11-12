#!/usr/bin/env python3
# =============================================================
# StormGlass - attack path finder v0
# Reads a Terraform plan JSON, builds a graph of the environment
# (who can reach what, who can become what, who can read what),
# and finds every route from the internet to sensitive data.
#
# read_env.py lists individual flaws. This connects them.
#
# Usage:  python find_paths.py plan.json
# Needs only the Python standard library.
# =============================================================

import json
import sys

INTERNET = "INTERNET"


# ---------- loading ------------------------------------------

def load_plan(plan_path):
    """Load the plan whatever its encoding (PowerShell writes UTF-16)."""
    with open(plan_path, "rb") as f:
        raw = f.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw.decode("utf-8-sig")
    else:
        text = raw.decode("utf-8")
    return json.loads(text)


def addr(res):
    """A resource's address, e.g. aws_instance.web"""
    return res.get("address") or f"{res.get('type')}.{res.get('name')}"


def collect_refs(node, known):
    """Find every reference to a known resource anywhere inside a
    configuration expression (handles nested blocks and lists)."""
    found = set()
    if isinstance(node, dict):
        for ref in node.get("references") or []:
            if isinstance(ref, str):
                parts = ref.split(".")
                if len(parts) >= 2 and ".".join(parts[:2]) in known:
                    found.add(".".join(parts[:2]))
        for value in node.values():
            found |= collect_refs(value, known)
    elif isinstance(node, list):
        for item in node:
            found |= collect_refs(item, known)
    return found


def label(res_values, fallback):
    tags = (res_values or {}).get("tags") or {}
    return tags.get("Name") or (res_values or {}).get("name") or fallback


# ---------- building the graph -------------------------------

def build_graph(plan):
    planned = (plan.get("planned_values") or {}).get("root_module") or {}
    config = (plan.get("configuration") or {}).get("root_module") or {}

    values = {addr(r): (r.get("values") or {}) for r in planned.get("resources") or []}
    rtype = {addr(r): r.get("type") for r in planned.get("resources") or []}
    expr = {addr(r): (r.get("expressions") or {}) for r in config.get("resources") or []}
    known = set(values)

    def refs(resource, attribute):
        return collect_refs(expr.get(resource, {}).get(attribute), known)

    def of_type(t):
        return [a for a in sorted(known) if rtype[a] == t]

    names = {a: label(values[a], a) for a in known}
    names[INTERNET] = "the internet"
    edges = []          # (source, target, explanation)

    # --- which instances sit behind which security groups
    sg_members = {}
    for inst in of_type("aws_instance"):
        for sg in refs(inst, "vpc_security_group_ids"):
            sg_members.setdefault(sg, []).append(inst)

    # --- network reachability from security group ingress rules
    for sg in of_type("aws_security_group"):
        members = sg_members.get(sg, [])
        planned_rules = values[sg].get("ingress") or []
        config_rules = expr.get(sg, {}).get("ingress")
        config_rules = config_rules if isinstance(config_rules, list) else []

        # rules open to the whole internet (values are known at plan time)
        for rule in planned_rules:
            if not isinstance(rule, dict):
                continue
            if "0.0.0.0/0" in (rule.get("cidr_blocks") or []):
                port = rule.get("from_port")
                for inst in members:
                    edges.append((INTERNET, inst,
                                  f"port {port} is open to 0.0.0.0/0"))

        # rules that admit another security group (lateral movement)
        lateral = []                      # (source security group, port)
        for rule in config_rules:         # shape 1: one entry per rule
            if not isinstance(rule, dict):
                continue
            port = (rule.get("from_port") or {}).get("constant_value")
            for src_sg in collect_refs(rule.get("security_groups"), known):
                lateral.append((src_sg, port))
        if not lateral:                   # shape 2: one expression for all rules
            sources = [s for s in refs(sg, "ingress")
                       if rtype.get(s) == "aws_security_group" and s != sg]
            ports = [r.get("from_port") for r in planned_rules
                     if isinstance(r, dict) and not (r.get("cidr_blocks") or [])]
            for src_sg in sources:
                for port in (ports or [None]):
                    lateral.append((src_sg, port))
        for src_sg, port in lateral:
            what = f"port {port}" if port is not None else "traffic"
            for src in sg_members.get(src_sg, []):
                for dst in members:
                    if src != dst:
                        edges.append((src, dst,
                                      f"{what} is allowed from "
                                      f"{names.get(src_sg, src_sg)}"))

    # --- identity: instance -> instance profile -> role
    profile_role = {}
    for prof in of_type("aws_iam_instance_profile"):
        for role in refs(prof, "role"):
            profile_role[prof] = role
    profile_by_name = {values[p].get("name"): p
                       for p in of_type("aws_iam_instance_profile")}

    for inst in of_type("aws_instance"):
        profiles = refs(inst, "iam_instance_profile")
        if not profiles:                      # fall back to matching by name
            p = profile_by_name.get(values[inst].get("iam_instance_profile"))
            profiles = {p} if p else set()
        for prof in profiles:
            role = profile_role.get(prof)
            if role:
                edges.append((inst, role,
                              f"instance profile '{names.get(prof, prof)}' "
                              f"lets it act as this role"))

    # --- permissions: role -> data, via attached policies
    for pol in of_type("aws_iam_role_policy"):
        try:
            doc = json.loads(values[pol].get("policy") or "{}")
        except (TypeError, ValueError):
            continue
        statements = doc.get("Statement") or []
        if isinstance(statements, dict):
            statements = [statements]
        for role in refs(pol, "role"):
            for st in statements:
                if st.get("Effect") != "Allow":
                    continue
                actions = st.get("Action") or []
                actions = [actions] if isinstance(actions, str) else actions
                resources = st.get("Resource") or []
                resources = [resources] if isinstance(resources, str) else resources
                s3_access = [a for a in actions if a in ("*", "s3:*")
                             or a.startswith("s3:Get") or a.startswith("s3:List")]
                if s3_access and "*" in resources:
                    for bucket in of_type("aws_s3_bucket"):
                        edges.append((role, bucket,
                                      f"policy '{names.get(pol, pol)}' allows "
                                      f"'{s3_access[0]}' on every resource"))

    merged = {}                       # one connection per pair, many reasons
    for src, dst, why in edges:
        reasons = merged.setdefault((src, dst), [])
        if why not in reasons:
            reasons.append(why)
    edges = [(src, dst, reasons) for (src, dst), reasons in merged.items()]

    targets = [a for a in sorted(known)
               if (values[a].get("tags") or {}).get("sensitivity") == "high"]
    return names, rtype, edges, targets


# ---------- searching it -------------------------------------

def all_paths(edges, start, goal):
    """Every route from start to goal that never revisits a node."""
    out = {}
    for src, dst, why in edges:
        out.setdefault(src, []).append((dst, why))
    found = []

    def walk(node, path, seen):
        if node == goal:
            found.append(path)
            return
        for nxt, why in out.get(node, []):
            if nxt not in seen:
                walk(nxt, path + [(nxt, why)], seen | {nxt})

    walk(start, [], {start})
    return sorted(found, key=len)


def main():
    if len(sys.argv) != 2:
        print("Usage: python find_paths.py plan.json")
        sys.exit(1)

    names, rtype, edges, targets = build_graph(load_plan(sys.argv[1]))

    line = "=" * 64
    print(line)
    print("  STORMGLASS - ATTACK PATHS FROM THE INTERNET")
    print(line)
    print(f"\n  Graph: {len(names) - 1} resources, {len(edges)} connections")
    print(f"  Sensitive targets: {len(targets)}")

    exposed = 0
    for target in targets:
        paths = all_paths(edges, INTERNET, target)
        print(f"\n{line}")
        print(f"  TARGET: {names[target]}  ({rtype[target]})")
        print(line)
        if not paths:
            print("\n  No path found from the internet with the rules modelled so far.")
            continue
        exposed += 1
        print(f"\n  {len(paths)} path(s) found. Shortest first.")
        for number, path in enumerate(paths, 1):
            print(f"\n  Path {number}  ({len(path)} steps)")
            print(f"    start: {names[INTERNET]}")
            for step, (node, why) in enumerate(path, 1):
                print(f"    {step}. -> {names[node]}  [{rtype[node]}]")
                print(f"         because {why[0]}")
                for other in why[1:]:
                    print(f"         also    {other}")

    print(f"\n{line}")
    print(f"  SUMMARY: {exposed} of {len(targets)} sensitive targets "
          f"reachable from the internet")
    print(line + "\n")


if __name__ == "__main__":
    main()
