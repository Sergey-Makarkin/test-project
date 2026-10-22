#!/usr/bin/env python3
"""Second-stage, strictly read-only Zabbix 6.4 alerting inventory.

Place beside zabbix_alert_preflight.py; reuse its token-safe API client.
Only calls template.get, host.get, discoveryrule.get, trigger.get, item.get.
Never displays auth tokens, passwords, hostnames or host IDs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import re
import sys

from zabbix_alert_preflight import Zabbix, read_env

ENV = "/etc/maintenance-portal/portal.env"
AVAIL_NAME = re.compile(r"agent.{0,30}(not available|unavailable|unreachable)|"
                        r"(not available|unavailable|unreachable).{0,30}agent|"
                        r"(host|server|system).{0,30}(down|offline|unreachable)|"
                        r"(icmp|ping|no data|nodata)", re.IGNORECASE)
AVAIL_KEYS = ("agent.ping", "icmpping", "zabbix[host,", "zabbix[proxy,")
MAX_TEMPLATES = 30


def safe(text: object, names: set[str]) -> str:
    s = str(text or "")
    for name in sorted(names, key=len, reverse=True):
        if len(name) >= 4:
            s = re.sub(re.escape(name), "<HOST>", s, flags=re.IGNORECASE)
    return s[:210]


def template_ancestry(api: Zabbix, template_id: str):
    queue = [str(template_id)]
    found = {}
    while queue and len(found) < MAX_TEMPLATES:
        todo = [tid for tid in queue if tid not in found]
        queue = []
        if not todo:
            break
        result = api.call("template.get", {
            "templateids": todo,
            "output": ["templateid", "name"],
            "selectParentTemplates": ["templateid", "name"],
        })
        for templ in result:
            tid = str(templ["templateid"])
            found[tid] = templ
            for parent in templ.get("parentTemplates", []):
                pid = str(parent["templateid"])
                if pid not in found:
                    queue.append(pid)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only discovery/availability diagnostics; no changes, no mail")
    parser.add_argument("--env", default=ENV)
    parser.add_argument("--template-id", default="10081")
    args = parser.parse_args()
    settings = read_env(args.env)
    token = settings.get("ZABBIX_API_TOKEN") or settings.get("ZABBIX_TOKEN")
    if not token:
        raise RuntimeError("Missing API token in portal.env")
    api = Zabbix(settings.get("ZABBIX_API_URL", "http://127.0.0.1/zabbix/api_jsonrpc.php"), token)

    hosts = api.call("host.get", {
        "templateids": [str(args.template_id)],
        "output": ["hostid", "host", "name", "status"],
        "selectParentTemplates": ["templateid"],
    })
    hosts = [h for h in hosts if str(h.get("status")) == "0" and any(
        str(x.get("templateid")) == str(args.template_id) for x in h.get("parentTemplates", [])
    )]
    ids = [str(h["hostid"]) for h in hosts]
    if not ids:
        raise RuntimeError("No direct-template enabled Windows hosts")
    hostnames = set()
    for h in hosts:
        hostnames.update(filter(None, (str(h.get("host", "")), str(h.get("name", "")))))

    print("===== WINDOWS SCOPE =====")
    print("Direct template ID:", args.template_id)
    print("Enabled Windows hosts:", len(ids))

    print("\n===== TEMPLATE ANCESTRY =====")
    templates = template_ancestry(api, str(args.template_id))
    for tid, t in sorted(templates.items(), key=lambda kv: kv[1].get("name", "")):
        print(f"  {tid}: {t.get('name', '')}")
    if len(templates) == MAX_TEMPLATES:
        print("  WARNING: template ancestry capped")

    print("\n===== WINDOWS SERVICE LLD AND OVERRIDES =====")
    rules = api.call("discoveryrule.get", {
        "templateids": list(templates),
        "output": ["itemid", "name", "key_", "status", "delay"],
        "selectFilter": "extend",
        "selectOverrides": "extend",
        "selectTriggers": ["triggerid", "description", "priority", "status"],
    })
    srules = [r for r in rules if "service" in str(r.get("key_", "")).lower() or
              "service" in str(r.get("name", "")).lower()]
    if not srules:
        print("No service LLD in template ancestry. Checking first enabled Windows host...")
        rules = api.call("discoveryrule.get", {
            "hostids": [ids[0]],
            "output": ["itemid", "name", "key_", "status", "delay"],
            "selectFilter": "extend",
            "selectOverrides": "extend",
            "selectTriggers": ["triggerid", "description", "priority", "status"],
        })
        srules = [r for r in rules if "service" in str(r.get("key_", "")).lower() or
                  "service" in str(r.get("name", "")).lower()]
    print("Service LLD rules:", len(srules))
    for rule in srules[:10]:
        print(f"  Rule: {safe(rule.get('name'), hostnames)} | key={rule.get('key_')} | status={rule.get('status')} | delay={rule.get('delay')}")
        filt = rule.get("filter") or {}
        fc = filt.get("conditions", [])
        print("   Filter conditions:", len(fc))
        for c in fc[:8]:
            print("    ", str(c.get("macro", "")), "operator=", c.get("operator", ""), "value=", safe(c.get("value", ""), hostnames))
        protos = rule.get("triggers") or []
        print("   Trigger prototypes:", len(protos))
        for p in protos[:5]:
            print(f"     priority={p.get('priority')} enabled_status={p.get('status')} name={safe(p.get('description'),hostnames)}")
        overrides = rule.get("lld_rule_overrides") or rule.get("overrides") or []
        print("   Existing overrides:", len(overrides))
        for override in overrides[:10]:
            print("     name:", safe(override.get("name"), hostnames))
            for cond in (override.get("filter") or {}).get("conditions", [])[:7]:
                print("       filter:", cond.get("macro"), "operator=", cond.get("operator"), "value=", safe(cond.get("value"), hostnames))
            for op in (override.get("operations") or [])[:5]:
                # The API may represent operations as objects including opobject/opstatus/opseverity.
                print("       operation:", {k: op.get(k) for k in ("opobject", "operator", "value", "opstatus", "opseverity") if k in op})

    print("\n===== HOST AVAILABILITY TRIGGER CANDIDATES =====")
    triggers = api.call("trigger.get", {
        "hostids": ids,
        "output": ["triggerid", "description", "expression", "priority", "status"],
        "selectItems": ["key_"],
        "selectTags": ["tag", "value"],
    })
    candidates = []
    tag_values = Counter()
    keys = Counter()
    for tr in triggers:
        if str(tr.get("status", "0")) != "0":
            continue
        tags = tr.get("tags") or []
        scope_available = any(str(t.get("tag", "")).lower() == "scope" and
                              "avail" in str(t.get("value", "")).lower() for t in tags)
        ks = [str(i.get("key_", "")) for i in tr.get("items", [])]
        key_hit = any(k.startswith(AVAIL_KEYS) for k in ks)
        name_hit = bool(AVAIL_NAME.search(str(tr.get("description", ""))))
        if scope_available or key_hit or name_hit:
            candidates.append(tr)
            for tag in tags:
                if str(tag.get("tag", "")).lower() in ("scope", "component", "class"):
                    tag_values[(str(tag.get("tag")), str(tag.get("value")))] += 1
            for k in ks:
                if not k.startswith("service.info["):
                    keys[k.split("[")[0]] += 1
    print("Availability candidates:", len(candidates))
    print("Candidate severities:", dict(sorted(Counter(int(t.get("priority", 0)) for t in candidates).items())))
    print("Candidate tag values:", dict(tag_values.most_common(10)))
    print("Candidate item key types:", dict(keys.most_common(10)))
    unique_examples = {}
    for t in candidates:
        desc = safe(t.get("description", ""), hostnames)
        if desc not in unique_examples:
            unique_examples[desc] = t
    for desc, tr in list(unique_examples.items())[:15]:
        print(f"  priority={tr.get('priority')} name={desc}")
        # Do not expose full expressions: they may contain internal hostnames.

    print("\n===== RELEVANT ITEM KEYS IN WINDOWS HOSTS =====")
    for query in ("agent.ping", "icmpping", "zabbix[host,"):
        found = api.call("item.get", {
            "hostids": ids,
            "output": ["itemid", "key_", "type", "status"],
            "search": {"key_": query},
        })
        found = [x for x in found if str(x.get("status", "0")) == "0"]
        key_counter = Counter(x.get("key_", "") for x in found)
        print(f"  Search key contains {query}: {len(found)} enabled items")
        for key, qty in key_counter.most_common(4):
            print("   ", key, ":", qty)

    print("\n===== RESULT =====")
    print("Read-only diagnostic finished; no Zabbix writes, no SMTP, no change to portal database.")


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        # Do not display API payload or credentials on failure.
        print(f"ERROR ({type(ex).__name__}): {str(ex)[:180]}", file=sys.stderr)
        sys.exit(1)
