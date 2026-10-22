#!/usr/bin/env python3
"""Read-only inventory for planned Zabbix 6.4 Windows alert aggregation.

Reads the existing Maintenance Portal env; makes only *.get JSON-RPC calls.
No SMTP, no Zabbix mutations, no SQLite mutations, no password/token logging.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

import requests

DEFAULT_ENV = "/etc/maintenance-portal/portal.env"
DEFAULT_DB = "/var/lib/maintenance-portal/audit_demo.sqlite3"
SEVERITIES = {0:"Not classified",1:"Information",2:"Warning",3:"Average",4:"High",5:"Disaster"}


def read_env(path):
    settings = {}
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            settings[key.strip()] = value.strip().strip('"').strip("'")
    return settings


class Zabbix:
    def __init__(self, url, token):
        self.url, self.token, self.req_id = url, token, 0
        self.session = requests.Session()

    def call(self, method, params):
        self.req_id += 1
        headers = {
            "Content-Type": "application/json-rpc",
            "Authorization": f"Bearer {self.token}",
        }
        payload = {"jsonrpc":"2.0", "method":method, "params":params, "id":self.req_id}
        try:
            response = self.session.post(self.url, json=payload, headers=headers, timeout=(4, 35))
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise RuntimeError(f"API request {method} failed ({type(exc).__name__}): {exc}") from exc
        if "error" in result:
            err = result["error"]
            # Zabbix error data may contain identifiers but no token should be emitted.
            raise RuntimeError(f"API {method}: code={err.get('code')} message={err.get('message')} data={err.get('data')}")
        return result["result"]


def print_severity_summary(counter, *, prefix="  "):
    print(prefix + " | ".join(f"{SEVERITIES[i]}={counter[i]}" for i in range(6)))


def inventory(api, template_id):
    print("===== ZABBIX API =====")
    print("API version:", api.call("apiinfo.version", {}))
    hosts = api.call("host.get", {
        "templateids": [str(template_id)],
        "output": ["hostid", "name", "status", "maintenance_status"],
        "selectParentTemplates": ["templateid"],
    })
    hosts = [h for h in hosts if str(h.get("status")) == "0" and any(
        str(t.get("templateid")) == str(template_id) for t in h.get("parentTemplates", [])
    )]
    host_ids = sorted({str(h["hostid"]) for h in hosts})
    print("\n===== WINDOWS SCOPE =====")
    print(f"Direct template {template_id}, enabled Windows hosts: {len(host_ids)}")
    print(f"Hosts with Zabbix maintenance status=1: {sum(str(h.get('maintenance_status')) == '1' for h in hosts)}")
    if not host_ids:
        print("STOP: no matching hosts. Check template ID and host permissions.")
        return

    triggers = api.call("trigger.get", {
        "hostids": host_ids,
        "output": ["triggerid", "description", "priority", "status"],
        "selectItems": ["key_"],
        "selectHosts": ["hostid"],
    })
    service_triggers = {}
    reachability_triggers = {}
    other_triggers = {}
    def classify(tr):
        keys = [str(item.get("key_", "")) for item in tr.get("items", [])]
        if any(k.startswith("service.info[") for k in keys):
            return "service"
        if any(k.startswith("agent.ping") or k.startswith("icmpping") for k in keys):
            return "availability_candidate"
        return "other"

    counts = {name: Counter() for name in ("service", "availability_candidate", "other")}
    all_triggers = {}
    for tr in triggers:
        if str(tr.get("status", "0")) != "0":
            continue
        kind = classify(tr)
        all_triggers[str(tr["triggerid"])] = kind
        counts[kind][int(tr.get("priority", 0))] += 1
        if kind == "service": service_triggers[str(tr["triggerid"])] = tr
        elif kind == "availability_candidate": reachability_triggers[str(tr["triggerid"])] = tr
        else: other_triggers[str(tr["triggerid"])] = tr
    print("\n===== ENABLED TRIGGERS =====")
    print(f"Total enabled triggers returned: {len(all_triggers)}")
    for k, label in [("service", "Windows service.info"), ("availability_candidate", "Host reachability candidates (agent.ping/icmpping)"), ("other", "Other")]:
        print(f"{label}: {sum(counts[k].values())}")
        print_severity_summary(counts[k])
    print("Note: availability candidates do NOT prove that a real unavailable-host trigger exists.")
    print("Note: custom nodata()/internal availability triggers may require separate classification.")
    if counts["service"][4] + counts["service"][5] == 0:
        print("WARNING: zero High/Disaster Windows service triggers: no service alerts under agreed severity policy.")

    problems = api.call("problem.get", {
        "hostids": host_ids,
        "source": 0,
        "object": 0,
        "output": ["eventid", "objectid", "clock", "severity", "suppressed", "r_eventid"],
        "selectTags": "extend",
        "selectSuppressionData": "extend",
    })
    problems_by_kind = {k: Counter() for k in ("service", "availability_candidate", "other")}
    problem_tag_keys = Counter()
    suppressed = 0
    for p in problems:
        kind = all_triggers.get(str(p.get("objectid")), "other")
        problems_by_kind[kind][int(p.get("severity", 0))] += 1
        suppressed += str(p.get("suppressed", "0")) == "1"
        for tag in p.get("tags", []):
            problem_tag_keys[str(tag.get("tag", ""))] += 1
    print("\n===== OPEN TRIGGER PROBLEMS =====")
    print(f"Total open: {len(problems)}; suppressed: {suppressed}; unsuppressed: {len(problems)-suppressed}")
    for kind, label in [("service", "Service problems"), ("availability_candidate", "Reachability candidate problems"), ("other", "Other/unclassified problems")]:
        print(f"{label}: {sum(problems_by_kind[kind].values())}")
        print_severity_summary(problems_by_kind[kind])
    print("Event tag keys (no values):", ", ".join(f"{k}:{v}" for k, v in problem_tag_keys.most_common(12)) or "none")

    since = int(time.time()) - 86400
    recent = api.call("event.get", {
        "hostids": host_ids,
        "source": 0, "object": 0,
        "time_from": since,
        "output": ["eventid", "objectid", "clock", "value", "severity", "r_eventid"],
        "sortfield": ["clock", "eventid"],
        "sortorder": "DESC",
        "limit": 500,
    })
    recent_counts = Counter(str(e.get("value", "?")) for e in recent)
    print("\n===== LAST 24 HOURS (up to 500 newest events) =====")
    print(f"Event sample size={len(recent)}; PROBLEM(value=1)={recent_counts['1']}; OK(value=0)={recent_counts['0']}")
    if len(recent) == 500:
        print("WARNING: 500 event limit reached. A production collector must use pagination/cursor.")

    print("\n===== EXISTING ACTIONS (READ ONLY) =====")
    try:
        actions = api.call("action.get", {"filter": {"eventsource": 0}, "output": ["actionid", "name", "status", "eventsource"]})
        print(f"Trigger actions: {len(actions)}; enabled: {sum(str(a.get('status')) == '0' for a in actions)}")
        if any(str(a.get('status')) == '0' for a in actions):
            print("WARNING: active Zabbix actions may cause duplicate email when our aggregator is enabled.")
    except RuntimeError as exc:
        print("Action listing unavailable:", str(exc)[:160])
    print("\n===== READ-ONLY RESULT =====")
    print("No Zabbix objects modified, no SMTP touched, no notifications generated.")


def project_db_probe(db_path):
    print("\n===== PORTAL PROJECT DATABASE (READ ONLY) =====")
    p = Path(db_path)
    if not p.is_file():
        print("Portal DB not found at configured path.")
        return
    try:
        db = sqlite3.connect(p.as_uri() + "?mode=ro", uri=True, timeout=5)
        cur = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        names = [str(r[0]) for r in cur.fetchall()]
        relevant = [n for n in names if any(x in n.lower() for x in ("project", "group", "assignment"))]
        print("Project-related tables:", ", ".join(relevant) or "none recognized")
        # Do not reveal project names / staff identifiers in shared output.
        for table in relevant:
            if not table.replace('_','').isalnum():
                continue
            n = db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            print(f"  {table}: rows={n}")
        db.close()
    except (OSError, sqlite3.Error) as exc:
        print("SQLite read-only probe failed:", type(exc).__name__, str(exc)[:100])


def main():
    parser = argparse.ArgumentParser(description="Read-only Zabbix alert readiness, no SMTP or writes")
    parser.add_argument("--env", default=DEFAULT_ENV)
    parser.add_argument("--template-id", default="10081")
    args = parser.parse_args()
    conf = read_env(args.env)
    token = conf.get("ZABBIX_API_TOKEN") or conf.get("ZABBIX_TOKEN")
    if not token:
        raise RuntimeError("No ZABBIX_API_TOKEN/ZABBIX_TOKEN found in env file (values not printed)")
    url = conf.get("ZABBIX_API_URL") or "http://127.0.0.1/zabbix/api_jsonrpc.php"
    if not url.startswith("http://127.0.0.1/") and not url.startswith("https://"):
        print("NOTICE: API URL is not HTTPS or localhost HTTP; check network confidentiality.")
    api = Zabbix(url, token)
    inventory(api, args.template_id)
    project_db_probe(conf.get("PORTAL_DB_PATH", DEFAULT_DB))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, KeyError, requests.RequestException) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
