#!/usr/bin/env python3
"""Zabbix 6.4 alert aggregator, Stage 3: Email previews, NO SMTP.

Read-only Zabbix and Portal configuration, separate writable preview-state DB.
Authoritative recipient/critical-service policy is imported from the INSTALLED
Maintenance Portal's alert_settings.py. No arbitrary example recipients.

No SMTP implementation, no Zabbix write methods, no changes to Portal DB.
A new Stage 3 state file is used; Stage 1 state/cursor remains untouched.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import re
from contextlib import closing
import fcntl
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import requests

DEFAULT_ENV = '/etc/maintenance-portal/portal.env'
DEFAULT_PORTAL_DB = '/var/lib/maintenance-portal/audit_demo.sqlite3'
DEFAULT_STATE_DB = '/var/lib/mportal-alerting/dryrun_stage3.sqlite3'
DEFAULT_PORTAL_CODE = '/opt/maintenance-portal-demo'
DEFAULT_FROM = 'mportal@biokob.com'
PAGE_SIZE = 500
WINDOW = 120
REMINDER = 14400


def read_env(path):
    values = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, val = line.split('=', 1)
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


class Zabbix:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.id = 0
        self.session = requests.Session()

    def call(self, method, params):
        if not method.endswith('.get') and method != 'apiinfo.version':
            raise ValueError('Read-only API methods permitted only')
        self.id += 1
        headers = {'Content-Type': 'application/json-rpc'}
        if method == 'apiinfo.version':
            params = []
        else:
            headers['Authorization'] = f'Bearer {self.token}'
        response = self.session.post(
            self.url,
            json={'jsonrpc': '2.0', 'method': method, 'params': params, 'id': self.id},
            headers=headers, timeout=(5, 35),
        )
        response.raise_for_status()
        result = response.json()
        if 'error' in result:
            err = result['error']
            raise RuntimeError(f'Zabbix API {method}: {err.get("message")} {err.get("data")}')
        return result['result']


def get_hosts(api, template):
    hosts = api.call('host.get', {
        'templateids': [str(template)],
        'output': ['hostid', 'host', 'name', 'status', 'maintenance_status'],
        'selectParentTemplates': ['templateid'],
    })
    return {str(h['hostid']): h for h in hosts
            if str(h.get('status')) == '0' and any(
                str(t['templateid']) == str(template) for t in h.get('parentTemplates', []))}


def get_project_routes(path):
    """Fail-closed on DB errors. No AD identities, SIDs or mailboxes read."""
    db = sqlite3.connect(f'file:{Path(path).resolve()}?mode=ro', uri=True)
    try:
        projects = dict(db.execute('SELECT id,name FROM mp_projects').fetchall())
        result = {}
        for hostid, projectid in db.execute('SELECT host_id,project_id FROM mp_project_hosts'):
            if projectid not in projects:
                raise RuntimeError('Invalid project reference; refusing mail route')
            result[str(hostid)] = f'PROJECT:{projectid}:{projects[projectid]}'
        return result
    finally:
        db.close()


def load_portal_settings(code_dir):
    """Load deployed policy code, not an independently reimplemented policy."""
    path = Path(code_dir) / 'alert_settings.py'
    if not path.is_file():
        raise RuntimeError(f'Portal policy module not found: {path}')
    spec = importlib.util.spec_from_file_location('mportal_deployed_alert_settings', str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError('Cannot load deployed Portal alert policy')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policies_for_hosts(portal_db, hostids, code_dir):
    """Read-only effective settings. Reject corrupt/ambiguous project routes."""
    project_routes = get_project_routes(portal_db)
    settings = load_portal_settings(code_dir)
    policies = {}
    for hostid in hostids:
        conf = settings.effective_for_host(portal_db, hostid)
        expected = project_routes.get(hostid)
        if expected is None and conf['scope'] != 'general':
            raise RuntimeError(f'Inconsistent general host route: {hostid}')
        if expected is not None and (conf['scope'] != 'project'
                                     or expected.split(':', 2)[1] != str(conf['project_id'])):
            raise RuntimeError(f'Inconsistent project host route: {hostid}')
        recipients = conf['recipients']
        if not isinstance(recipients, list) or not all(isinstance(x, str) for x in recipients):
            raise RuntimeError(f'Invalid recipient list for host: {hostid}')
        # Defensive revalidation: DB policy is not automatically trusted.
        if recipients != settings.normalize_recipients(','.join(recipients)):
            raise RuntimeError(f'Invalid/duplicate recipients for host: {hostid}')
        services = {}
        for item in conf['critical_services']:
            name = settings.service_name_validate(item['name']).casefold()
            level = int(item['severity'])
            if level not in (4, 5):
                raise RuntimeError(f'Invalid critical service severity: {hostid}')
            services[name] = level
        policies[hostid] = {**conf, 'critical_map': services}
    return policies, project_routes


def service_name_from_item_key(key):
    """Parse actual Zabbix service.info[short_name,state] item key."""
    if not key.startswith('service.info[') or not key.endswith(']'):
        return None
    try:
        params = next(csv.reader([key[len('service.info['):-1]], escapechar='\\',
                                 skipinitialspace=True, strict=True))
    except (csv.Error, StopIteration):
        return None
    if not params or not params[0].strip() or params[0].startswith('{#'):
        return None
    return params[0].strip()


def classify_trigger(t):
    if str(t.get('status')) != '0':
        return None
    keys = [i.get('key_', '') for i in t.get('items', [])]
    if any(k.startswith('service.info[') for k in keys):
        return 'service'
    if any(k == 'zabbix[host,agent,available]' for k in keys):
        return 'agent_unavailable'
    return None


def get_triggers(api, hostids):
    triggers = api.call('trigger.get', {
        'hostids': hostids, 'output': ['triggerid', 'status', 'priority', 'description'],
        'selectItems': ['key_'], 'selectHosts': ['hostid'],
    })
    indexed = {}
    for t in triggers:
        kind = classify_trigger(t)
        if not kind:
            continue
        owners = [str(h['hostid']) for h in t.get('hosts', []) if str(h['hostid']) in hostids]
        if len(owners) != 1:
            # Do not route ambiguous multi-host triggers to an arbitrary project.
            continue
        keys = [service_name_from_item_key(i.get('key_', '')) for i in t.get('items', [])]
        names = {n.casefold(): n for n in keys if n}
        if kind == 'service' and len(names) != 1:
            # Unknown/ambiguous service names must never bypass exclusions.
            continue
        indexed[str(t['triggerid'])] = {
            'hostid': owners[0], 'kind': kind,
            'service_name': next(iter(names.values())) if kind == 'service' else None,
            'priority': int(t.get('priority', 0)),
        }
    return indexed


def get_open_problems(api, hostids):
    items = api.call('problem.get', {
        'hostids': hostids, 'source': 0, 'object': 0,
        'output': ['eventid', 'objectid', 'clock', 'severity', 'name', 'suppressed', 'r_eventid'],
        'selectSuppressionData': 'extend',
    })
    return {str(p['eventid']): p for p in items}


def get_latest_eventid(api, hostids):
    latest = api.call('event.get', {
        'hostids': hostids, 'source': 0, 'object': 0,
        'output': ['eventid'], 'sortfield': 'eventid', 'sortorder': 'DESC', 'limit': 1,
    })
    return int(latest[0]['eventid']) if latest else 0


def poll_new_events(api, hostids, after_id):
    """Full cursor pagination; no arbitrary top-500 truncation."""
    events = []
    cursor = int(after_id)
    while True:
        batch = api.call('event.get', {
            'hostids': hostids, 'source': 0, 'object': 0,
            'eventid_from': str(cursor + 1),
            'output': ['eventid', 'objectid', 'value', 'clock', 'severity', 'name'],
            'sortfield': 'eventid', 'sortorder': 'ASC', 'limit': PAGE_SIZE,
        })
        if not batch:
            break
        new_cursor = max(int(e['eventid']) for e in batch)
        if new_cursor <= cursor:
            raise RuntimeError('Zabbix pagination did not advance')
        events.extend(batch)
        cursor = new_cursor
        if len(batch) < PAGE_SIZE:
            break
    return events, cursor


def ensure_state(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS candidates (
            eventid TEXT PRIMARY KEY, hostid TEXT NOT NULL,
            kind TEXT NOT NULL, name TEXT NOT NULL, severity INTEGER NOT NULL,
            born INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS host_notifications (
            hostid TEXT PRIMARY KEY, last_json TEXT NOT NULL DEFAULT '[]',
            pending_since INTEGER, last_preview_at INTEGER,
            route_key TEXT
        );
    ''')


def setting(db, key):
    result = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return result[0] if result else None


def set_setting(db, key, value):
    db.execute('INSERT INTO settings(key,value) VALUES (?,?) '
               'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))


def active_candidate_snapshot(db, problems, triggers, policies):
    """Only new candidate events that still exist, with unchanged qualifying severity."""
    result = {}
    suppressed_hosts = set()
    for eventid, hostid, kind, name, severity, born in db.execute(
        'SELECT eventid,hostid,kind,name,severity,born FROM candidates'
    ):
        p = problems.get(eventid)
        if not p:
            continue
        if str(p.get('suppressed', '0')) == '1' or p.get('suppression_data'):
            suppressed_hosts.add(hostid)
            continue
        meta = triggers.get(str(p.get('objectid')))
        if not meta or meta['hostid'] != hostid or meta['kind'] != kind:
            continue
        policy = policies.get(hostid)
        if policy is None:
            raise RuntimeError(f'Missing host policy for {hostid}')
        if kind == 'service':
            service = meta.get('service_name')
            required = policy['critical_map'].get(service.casefold()) if service else None
            if required is None:
                continue  # Admin did not mark this service as critical, or excluded it.
        else:
            required = 4  # Agent availability does not use Windows service rules.
        if int(p.get('severity', 0)) < required or int(severity) < required:
            continue
        result.setdefault(hostid, []).append({
            'id': eventid, 'name': str(p.get('name') or name),
            'kind': kind, 'severity': int(p['severity']),
        })
    for incidents in result.values():
        incidents.sort(key=lambda x: int(x['id']))
    return result, suppressed_hosts


def render_preview(hostid, host, policy, reason, previous, current, now,
                   sender=DEFAULT_FROM, open_problem_ids=None,
                   prefix='WOULD_EMAIL'):
    prev_ids = {x['id'] for x in previous}
    curr_ids = {x['id'] for x in current}
    added = [x['name'] for x in current if x['id'] not in prev_ids]
    open_problem_ids = set(open_problem_ids or ())
    recovered = [x['name'] for x in previous
                 if x['id'] not in curr_ids and x['id'] not in open_problem_ids]
    no_longer_monitored = [x['name'] for x in previous
                           if x['id'] not in curr_ids and x['id'] in open_problem_ids]
    subject = ('RECOVERED' if not current else 'PROBLEM' if not previous else 'UPDATE')
    if no_longer_monitored:
        subject = 'POLICY CHANGE'
    if reason == 'REMINDER':
        subject = 'REMINDER'
    if not policy['recipients']:
        raise RuntimeError('Attempted to preview send without configured recipients')
    route = ('GENERAL' if policy['scope'] == 'general' else
             f'PROJECT:{policy["project_id"]}:{policy["project_name"]}')
    print(prefix + ' ' + json.dumps({
        'utc_epoch': now, 'route': route, 'hostid': hostid,
        'from': sender, 'to': policy['recipients'],
        'host': host.get('name') or host.get('host'),
        'subject': f'[{subject}] Windows {host.get("name") or host.get("host")}',
        'reason': reason, 'active_count': len(current),
        'active': [x['name'] for x in current],
        'new': added, 'recovered': recovered,
        'no_longer_monitored': no_longer_monitored,
        'body_text': ('Windows host: ' + str(host.get('name') or host.get('host')) + '\n'
                      + 'Project: ' + str(policy.get('project_name') or 'GENERAL') + '\n'
                      + 'Status: ' + subject + '\n'
                      + 'Active problems (' + str(len(current)) + '):\n'
                      + '\n'.join(' - ' + x['name'] for x in current) + '\n'
                      + 'New: ' + ', '.join(added) + '\n'
                      + 'Recovered: ' + ', '.join(recovered) + '\n'
                      + 'No longer monitored: ' + ', '.join(no_longer_monitored)),
    }, ensure_ascii=False))


def advance_notifications(db, hosts, policies, problems, triggers, now):
    active, suppressed_hosts = active_candidate_snapshot(db, problems, triggers, policies)
    known_hosts = set(active)
    known_hosts.update(r[0] for r in db.execute('SELECT hostid FROM host_notifications'))
    previews = 0
    waiting = 0
    suppressed = 0
    for hostid in sorted(known_hosts, key=int):
        host = hosts.get(hostid)
        if host is None:
            print(f'SKIP hostid={hostid} no longer in enabled Windows scope')
            continue
        policy = policies[hostid]
        route_key = json.dumps({'scope': policy['scope'],
                                'project_id': policy['project_id'],
                                'recipients': policy['recipients']}, sort_keys=True)
        old_row = db.execute('SELECT last_json,pending_since,last_preview_at,route_key '
                             'FROM host_notifications WHERE hostid=?', (hostid,)).fetchone()
        if old_row and old_row[3] != route_key:
            # Do not deliver old-route incident details as a recovery to new team.
            print(f'ROUTE_CHANGED: hostid={hostid}; previous preview state reset')
            db.execute('DELETE FROM host_notifications WHERE hostid=?', (hostid,))
            old_row = None
        prev = json.loads(old_row[0]) if old_row else []
        since = old_row[1] if old_row else None
        last_at = old_row[2] if old_row else None
        curr = active.get(hostid, [])
        if hostid in suppressed_hosts or str(host.get('maintenance_status', '0')) == '1':
            # Conservative per-host pause: do not interpret suppression as recovery.
            suppressed += 1
            continue
        prev_ids = {x['id'] for x in prev}
        curr_ids = {x['id'] for x in curr}
        changed = prev_ids != curr_ids
        if changed:
            if since is None:
                since = now
            if now - since >= WINDOW and not policy['recipients']:
                print(f'WOULD_BLOCK_NO_RECIPIENTS hostid={hostid} scope={policy["scope"]}')
                waiting += 1
                # Hold pending event; never fall back to another project's recipients.
                db.execute('INSERT INTO host_notifications '
                           '(hostid,last_json,pending_since,last_preview_at,route_key) '
                           'VALUES (?,?,?,NULL,?) ON CONFLICT(hostid) DO UPDATE '
                           'SET pending_since=excluded.pending_since,route_key=excluded.route_key',
                           (hostid, json.dumps(prev), since, route_key))
            elif now - since >= WINDOW:
                render_preview(hostid, host, policy, 'CHANGED', prev, curr, now,
                               open_problem_ids=problems)
                db.execute('INSERT INTO host_notifications'
                           '(hostid,last_json,pending_since,last_preview_at,route_key) '
                           'VALUES (?,?,NULL,?,?) ON CONFLICT(hostid) DO UPDATE '
                           'SET last_json=excluded.last_json,pending_since=NULL,'
                           'last_preview_at=excluded.last_preview_at,route_key=excluded.route_key',
                           (hostid, json.dumps(curr), now, route_key))
                previews += 1
            else:
                db.execute('INSERT INTO host_notifications'
                           '(hostid,last_json,pending_since,last_preview_at,route_key) '
                           'VALUES (?,?,?,NULL,?) ON CONFLICT(hostid) DO UPDATE '
                           'SET pending_since=excluded.pending_since,route_key=excluded.route_key',
                           (hostid, json.dumps(prev), since, route_key))
                waiting += 1
        elif curr and last_at is not None and now - last_at >= REMINDER:
            if policy['recipients']:
                render_preview(hostid, host, policy, 'REMINDER', prev, curr, now,
                               open_problem_ids=problems)
                db.execute('UPDATE host_notifications SET last_preview_at=? WHERE hostid=?', (now, hostid))
                previews += 1
            else:
                print(f'WOULD_BLOCK_NO_RECIPIENTS hostid={hostid} scope={policy["scope"]}')
                waiting += 1
        elif since is not None:
            db.execute('UPDATE host_notifications SET pending_since=NULL WHERE hostid=?', (hostid,))
    return previews, waiting, suppressed


def run(api, portal_db, state_db, template, now, code_dir=DEFAULT_PORTAL_CODE):
    if not state_db.parent.exists():
        raise RuntimeError(f'State directory does not exist: {state_db.parent} (create explicitly)')
    hosts = get_hosts(api, template)
    if not hosts:
        raise RuntimeError('Zero enabled Windows hosts, refusing to change cursor')
    hostids = list(hosts)
    policies, routes = policies_for_hosts(portal_db, hostids, code_dir)
    triggers = get_triggers(api, hostids)
    problems = get_open_problems(api, hostids)
    # Finish all external reads before opening writable state DB.
    with closing(sqlite3.connect(state_db, timeout=10)) as db:
        ensure_state(db)
        old_cursor = setting(db, 'cursor')
        if old_cursor is None:
            latest = get_latest_eventid(api, hostids)
            set_setting(db, 'cursor', latest)
            set_setting(db, 'baseline_at', now)
            db.commit()
            print(f'BASELINE CREATED: cursor={latest}, open_problems={len(problems)}, '
                  f'hosts={len(hostids)}; no historical events notified')
            return
        events, cursor = poll_new_events(api, hostids, int(old_cursor))
        created = 0
        with db:
            for event in events:
                if str(event.get('value')) != '1' or int(event.get('severity', 0)) < 4:
                    continue
                tr = triggers.get(str(event.get('objectid')))
                if not tr:
                    continue
                eid = str(event['eventid'])
                # Only record new PROBLEM events; reconciliation decides if still open.
                db.execute('INSERT OR IGNORE INTO candidates(eventid,hostid,kind,name,severity,born) '
                           'VALUES(?,?,?,?,?,?)',
                           (eid, tr['hostid'], tr['kind'], str(event.get('name') or ''),
                            int(event['severity']), int(event['clock'])))
                created += 1
            previews, waiting, suppressed = advance_notifications(
                db, hosts, policies, problems, triggers, now)
            set_setting(db, 'cursor', cursor)
        print(f'DRY_RUN_POLICY: hosts={len(hosts)} project_hosts={len(routes)} '
              f'configured_routes={sum(bool(p["recipients"]) for p in policies.values())} '
              f'new_events={len(events)} '
              f'new_high_candidates={created} previews={previews} '
              f'waiting={waiting} suppressed_hosts={suppressed} cursor={cursor}')


def main():
    parser = argparse.ArgumentParser(description='Portal-integrated Zabbix email DRY_RUN (NO SMTP)')
    parser.add_argument('--env', default=DEFAULT_ENV)
    parser.add_argument('--portal-db', default=DEFAULT_PORTAL_DB)
    parser.add_argument('--state-db', default=DEFAULT_STATE_DB)
    parser.add_argument('--template-id', default='10081')
    parser.add_argument('--portal-code-dir', default=DEFAULT_PORTAL_CODE)
    parser.add_argument('--check-config', action='store_true',
                        help='Read effective routing/rules only; do not touch state DB')
    parser.add_argument('--sample-preview', action='store_true',
                        help='Print one clearly FAKE sample email; no state DB and no SMTP')
    parser.add_argument('--host-id', default='10917',
                        help='Host ID displayed in --check-config (default pilot ML2SRV01)')
    args = parser.parse_args()
    conf = read_env(args.env)
    token = conf.get('ZABBIX_API_TOKEN') or conf.get('ZABBIX_TOKEN')
    if not token:
        raise RuntimeError('Missing ZABBIX_API_TOKEN or ZABBIX_TOKEN')
    if conf.get('PORTAL_PROJECT_RBAC') != '1':
        raise RuntimeError('Project RBAC not enabled: refusing ambiguous routes')
    url = conf.get('ZABBIX_API_URL') or 'http://127.0.0.1/zabbix/api_jsonrpc.php'
    if not (url.startswith('https://') or url.startswith('http://127.0.0.1/')):
        raise RuntimeError('Refusing non-TLS remote Zabbix API')
    api = Zabbix(url, token)
    if args.check_config or args.sample_preview:
        hosts = get_hosts(api, args.template_id)
        if not hosts:
            raise RuntimeError('No Windows hosts found')
        policies, routes = policies_for_hosts(args.portal_db, list(hosts), args.portal_code_dir)
        triggers = get_triggers(api, list(hosts))
        service_triggers = [t for t in triggers.values() if t['kind'] == 'service']
        agent_triggers = [t for t in triggers.values() if t['kind'] == 'agent_unavailable']
        policy_critical_triggers = [t for t in service_triggers if
                                    t['service_name'].casefold() in
                                    policies[t['hostid']]['critical_map']]
        print('CONFIG CHECK ONLY: no state DB accessed, no SMTP capability')
        print(f'hosts={len(hosts)} project_hosts={len(routes)} '
              f'configured_routes={sum(bool(p["recipients"]) for p in policies.values())}')
        print(f'service_triggers_parsed={len(service_triggers)} '
              f'agent_availability_triggers={len(agent_triggers)} '
              f'policy_critical_triggers={len(policy_critical_triggers)} '
              f'policy_critical_high_or_disaster={sum(t["priority"] >= 4 for t in policy_critical_triggers)}')
        conf = policies.get(str(args.host_id))
        if conf is None:
            raise RuntimeError(f'Host {args.host_id} not in enabled Windows scope')
        print('HOST_CONFIG ' + json.dumps({
            'hostid': str(args.host_id), 'host': hosts[str(args.host_id)].get('name'),
            'scope': conf['scope'], 'project': conf['project_name'],
            'to': conf['recipients'], 'critical_services': conf['critical_services'],
        }, ensure_ascii=False))
        if args.sample_preview:
            if not conf['recipients'] or not conf['critical_services']:
                print('SAMPLE_NOT_READY: configure a recipient and a critical service in Admin Panel')
            else:
                service = conf['critical_services'][0]['name']
                render_preview(str(args.host_id), hosts[str(args.host_id)], conf,
                               'CHANGED', [], [{'id':'SYNTHETIC-TEST', 'name':
                               '[SAMPLE ONLY] ' + service + ' is not running'}],
                               int(time.time()), prefix='SAMPLE_EMAIL')
        return
    # Atomic lock prevents duplicate runs from a future timer.
    lockfile = Path(args.state_db + '.lock')
    if not lockfile.parent.exists():
        raise RuntimeError(f'Create private state directory first: {lockfile.parent}')
    with open(lockfile, 'a+', encoding='utf-8') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(api, args.portal_db,
            Path(args.state_db), args.template_id, int(time.time()), args.portal_code_dir)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, requests.RequestException, sqlite3.Error, OSError, BlockingIOError) as exc:
        print(f'ERROR: {type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(1)
