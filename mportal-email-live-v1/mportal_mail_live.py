#!/usr/bin/env python3
"""Production email worker for Zabbix 6.4 and Maintenance Portal.

Zabbix: read-only API; Portal SQLite: read-only.
State/outbox: dedicated SQLite. Mail is LIVE only with explicit --live.
At-least-once SMTP submission (not guaranteed final mailbox delivery).
"""
from __future__ import annotations

import argparse
from contextlib import closing
from email.message import EmailMessage
import fcntl
import json
import os
from pathlib import Path
import smtplib
import sqlite3
import sys
import time
import uuid

import requests
import zabbix_mail_policy_dryrun as policy

STATE_DB = '/var/lib/mportal-live/alerts.sqlite3'
WINDOW = 120
REMINDER = 4 * 3600
MAX_DELIVERY_PER_RUN = 30
FROM_ADDR = 'mportal@example.com'


def key_for(p):
    """Any recipient/project/critical rule change invalidates queued mail."""
    return json.dumps({
        'scope': p['scope'], 'project_id': p['project_id'],
        'recipients': p['recipients'],
        'critical': p['critical_map'],
    }, sort_keys=True, ensure_ascii=False)


def record(hostid, host, policy_data, previous, current, reason, now, open_ids):
    prev_ids = {x['id'] for x in previous}
    curr_ids = {x['id'] for x in current}
    newly = [x['name'] for x in current if x['id'] not in prev_ids]
    recovered = [x['name'] for x in previous if x['id'] not in curr_ids and x['id'] not in open_ids]
    excluded = [x['name'] for x in previous if x['id'] not in curr_ids and x['id'] in open_ids]
    status = 'REMINDER' if reason == 'REMINDER' else ('RECOVERED' if not current else 'UPDATE' if previous else 'PROBLEM')
    if excluded and reason != 'REMINDER':
        status = 'POLICY CHANGE'
    hostname = host.get('name') or host.get('host') or hostid
    return {
        'hostid': hostid, 'host': hostname, 'status': status,
        'project': policy_data.get('project_name') or 'GENERAL',
        'reason': reason, 'current': current, 'new': newly,
        'recovered': recovered, 'excluded': excluded, 'created_at': now,
    }


def make_message(rec, addr, msgid):
    def safe(s):
        return str(s).replace('\r', ' ').replace('\n', ' ')[:200]
    msg = EmailMessage()
    msg['From'] = FROM_ADDR
    msg['To'] = addr
    msg['Subject'] = f"[MPortal][{rec['status']}] Windows {safe(rec['host'])}"
    msg['Message-ID'] = msgid
    msg.set_content('\n'.join([
        'MPortal Windows Alerting',
        f"Host: {rec['host']} (Zabbix hostid={rec['hostid']})",
        f"Project: {rec['project']}",
        f"Status: {rec['status']}",
        f"Active problems: {len(rec['current'])}",
        '', 'Active:',
        *['  - ' + str(x['name']) for x in rec['current']],
        '', 'New:', *['  + ' + x for x in rec['new']],
        '', 'Recovered:', *['  - ' + x for x in rec['recovered']],
        '', 'No longer monitored:', *['  ~ ' + x for x in rec['excluded']],
        '', 'Generated from Zabbix monitoring. Reply is not monitored.',
    ]))
    return msg


def ensure_state(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS candidates(
        eventid TEXT PRIMARY KEY,hostid TEXT NOT NULL,kind TEXT NOT NULL,
        name TEXT NOT NULL,severity INTEGER NOT NULL,born INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS host_notifications(
        hostid TEXT PRIMARY KEY,last_json TEXT NOT NULL DEFAULT '[]',
        pending_since INTEGER,last_sent_at INTEGER,policy_key TEXT);
    CREATE TABLE IF NOT EXISTS outbox(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostid TEXT NOT NULL,policy_key TEXT NOT NULL,
        recipients_json TEXT NOT NULL,payload_json TEXT NOT NULL,
        accepted_json TEXT NOT NULL DEFAULT '[]',
        message_id TEXT NOT NULL UNIQUE,status TEXT NOT NULL
          CHECK(status IN ('queued','retry','accepted','cancelled')),
        created_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt INTEGER NOT NULL DEFAULT 0,last_error TEXT,
        completed_at INTEGER);
    CREATE UNIQUE INDEX IF NOT EXISTS pending_by_host ON outbox(hostid)
      WHERE status IN ('queued','retry');
    ''')


def get_setting(db, name):
    row = db.execute('SELECT value FROM settings WHERE key=?', (name,)).fetchone()
    return row[0] if row else None


def set_setting(db, name, value):
    db.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) '
               'DO UPDATE SET value=excluded.value', (name, str(value)))


def pending(db, hostid):
    return db.execute("SELECT id,payload_json,status FROM outbox WHERE hostid=? "
                      "AND status IN ('queued','retry')", (hostid,)).fetchone()


def cancel_pending(db, hostid, reason):
    db.execute("UPDATE outbox SET status='cancelled',last_error=? "
               "WHERE hostid=? AND status IN ('queued','retry')", (reason[:500], hostid))


def queue_mail(db, hostid, key, recipients, payload, now):
    pending_row = pending(db, hostid)
    pj = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if pending_row:
        if pending_row[1] != pj:
            # No recipients have been accepted unless an earlier attempt partly succeeded.
            # Cancel and recreate so accepted recipients are never resent for this payload.
            db.execute("UPDATE outbox SET status='cancelled',last_error='Superseded by new snapshot' "
                       'WHERE id=?', (pending_row[0],))
        else:
            return pending_row[0]
    mid = '<mportal-' + uuid.uuid4().hex + '@example.com>'
    return db.execute('''INSERT INTO outbox(
        hostid,policy_key,recipients_json,payload_json,message_id,status,created_at,next_attempt)
        VALUES(?,?,?,?,?,'queued',?,?)''',
        (hostid, key, json.dumps(recipients), pj, mid, now, now)).lastrowid


def schedule(db, hosts, policies, problems, triggers, now):
    active, suppressed = policy.active_candidate_snapshot(db, problems, triggers, policies)
    hostids = set(active)
    hostids.update(row[0] for row in db.execute('SELECT hostid FROM host_notifications'))
    hostids.update(row[0] for row in db.execute("SELECT hostid FROM outbox WHERE status IN ('queued','retry')"))
    enqueued = waiting = blocked = paused = 0
    for hid in sorted(hostids, key=int):
        if hid not in hosts:
            cancel_pending(db, hid, 'Host no longer in enabled Windows scope')
            continue
        p = policies[hid]
        route = key_for(p)
        row = db.execute('SELECT last_json,pending_since,last_sent_at,policy_key '
                         'FROM host_notifications WHERE hostid=?', (hid,)).fetchone()
        if row is not None and row[3] != route:
            cancel_pending(db, hid, 'Policy or recipient changed')
            db.execute('DELETE FROM host_notifications WHERE hostid=?', (hid,))
            row = None
            print(f'ROUTE_OR_POLICY_CHANGED hostid={hid} (discarding former notification state)')
        prev = json.loads(row[0]) if row else []
        since = row[1] if row else None
        last_sent = row[2] if row else None
        curr = active.get(hid, [])
        if hid in suppressed or str(hosts[hid].get('maintenance_status', '0')) == '1':
            cancel_pending(db, hid, 'Suppressed by Zabbix Maintenance')
            db.execute('INSERT INTO host_notifications(hostid,last_json,pending_since,last_sent_at,policy_key) '
                       'VALUES(?,?,NULL,?,?) ON CONFLICT(hostid) DO UPDATE '
                       'SET pending_since=NULL,policy_key=excluded.policy_key',
                       (hid, json.dumps(prev), last_sent, route))
            paused += 1
            continue
        changed = {x['id'] for x in prev} != {x['id'] for x in curr}
        reminder = (not changed and bool(curr) and last_sent is not None
                    and now - last_sent >= REMINDER)
        if not changed and not reminder:
            cancel_pending(db, hid, 'State returned to last delivered snapshot')
            db.execute('UPDATE host_notifications SET pending_since=NULL WHERE hostid=?',(hid,))
            continue
        if not p['recipients']:
            cancel_pending(db, hid, 'No recipients for current route')
            blocked += 1
            print(f'BLOCKED_NO_RECIPIENTS hostid={hid} scope={p["scope"]}')
            continue
        if changed:
            if since is None:
                since = now
            if now - since < WINDOW:
                waiting += 1
                db.execute('INSERT INTO host_notifications '
                           '(hostid,last_json,pending_since,last_sent_at,policy_key) VALUES(?,?,?,?,?) '
                           'ON CONFLICT(hostid) DO UPDATE SET pending_since=excluded.pending_since,policy_key=excluded.policy_key',
                           (hid, json.dumps(prev), since, last_sent, route))
                continue
        # Stable identity while queued: a retry must not be replaced every minute.
        snapshot_time = (last_sent + REMINDER) if reminder else since
        payload = record(hid, hosts[hid], p, prev, curr,
                         'REMINDER' if reminder else 'CHANGED', snapshot_time, set(problems))
        queue_mail(db, hid, route, p['recipients'], payload, now)
        db.execute('INSERT INTO host_notifications '
                   '(hostid,last_json,pending_since,last_sent_at,policy_key) VALUES(?,?,?,?,?) '
                   'ON CONFLICT(hostid) DO UPDATE SET pending_since=excluded.pending_since,policy_key=excluded.policy_key',
                   (hid, json.dumps(prev), since, last_sent, route))
        enqueued += 1
    return enqueued, waiting, blocked, paused


def submit_one(host, port, sender, addr, msg, smtp_factory=smtplib.SMTP):
    with smtp_factory(host, port, timeout=15) as smtp:
        code, _ = smtp.ehlo()
        if code != 250:
            raise smtplib.SMTPException(f'EHLO not accepted: {code}')
        refused = smtp.send_message(msg, from_addr=sender, to_addrs=[addr])
        if refused:
            raise smtplib.SMTPException(f'Recipient refused by relay: {refused}')


def deliver(db, smtp, portal_db, settings_module, hosts, policies, active, suppressed, now,
            smtp_factory=smtplib.SMTP):
    sent = failed = cancelled = 0
    rows = db.execute("SELECT id,hostid,policy_key,recipients_json,payload_json,accepted_json,message_id,attempts "
                      "FROM outbox WHERE status IN ('queued','retry') AND next_attempt<=? "
                      'ORDER BY id LIMIT ?', (now, MAX_DELIVERY_PER_RUN)).fetchall()
    for row in rows:
        oid, hid, required_key, to_json, payload_json, accepted_json, message_id, attempts = row
        host = hosts.get(hid)
        if host is None or hid in suppressed or str(host.get('maintenance_status', '0')) == '1':
            cancel_pending(db, hid, 'Host absent or Maintenance in progress')
            cancelled += 1
            continue
        # Fresh read before *each* queued email; current project/recipient must match.
        effective = settings_module.effective_for_host(portal_db, hid)
        live_policy = {**effective, 'critical_map': {
            x['name'].casefold(): int(x['severity']) for x in effective['critical_services']}}
        if key_for(live_policy) != required_key or key_for(policies[hid]) != required_key:
            cancel_pending(db, hid, 'Recipient/project/rule changed before SMTP')
            cancelled += 1
            continue
        payload = json.loads(payload_json)
        # Do not mail a PROBLEM which is no longer active before SMTP recovery.
        active_ids = {x['id'] for x in active.get(hid, [])}
        wanted_ids = {x['id'] for x in payload['current']}
        if wanted_ids != active_ids:
            cancel_pending(db, hid, 'Current incident snapshot changed before SMTP')
            cancelled += 1
            continue
        recipients = json.loads(to_json)
        accepted = set(json.loads(accepted_json))
        try:
            for addr in recipients:
                if addr in accepted:
                    continue
                message = make_message(payload, addr, message_id)
                submit_one(smtp['host'], smtp['port'], FROM_ADDR, addr, message, smtp_factory)
                accepted.add(addr)
                db.execute('UPDATE outbox SET accepted_json=? WHERE id=?',
                           (json.dumps(sorted(accepted)), oid))
                db.commit()  # Persist each successful recipient before attempting another.
                print(f'SMTP_ACCEPTED outbox={oid} hostid={hid} recipient={addr}')
            with db:
                db.execute("UPDATE outbox SET status='accepted',completed_at=?,last_error=NULL WHERE id=?",(now, oid))
                db.execute('''UPDATE host_notifications
                              SET last_json=?,last_sent_at=?,pending_since=NULL
                              WHERE hostid=? AND policy_key=?''',
                           (json.dumps(payload['current'], ensure_ascii=False), now, hid, required_key))
            sent += 1
        except (OSError, smtplib.SMTPException, ValueError) as exc:
            next_time = now + min(3600, 60 * (2 ** min(attempts, 6)))
            with db:
                db.execute("UPDATE outbox SET status='retry',attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?",
                           (next_time, (type(exc).__name__ + ': ' + str(exc))[:500], oid))
            print(f'SMTP_RETRY outbox={oid} hostid={hid} retry_at={next_time} error={type(exc).__name__}')
            failed += 1
    return sent, failed, cancelled


def run(api, portal_db, state_file, template_id, code_dir, now, live=True,
        smtp_factory=smtplib.SMTP):
    settings_mod = policy.load_portal_settings(code_dir)
    smtp = settings_mod.smtp_config(portal_db)  # Read admin-configured SMTP every cycle.
    if smtp['from'] != FROM_ADDR or smtp['auth'] or smtp['starttls']:
        raise RuntimeError('Unsafe SMTP config; refusing LIVE sending')
    hosts = policy.get_hosts(api, template_id)
    if not hosts:
        raise RuntimeError('No enabled Windows hosts')
    policies, routes = policy.policies_for_hosts(portal_db, list(hosts), code_dir)
    triggers = policy.get_triggers(api, list(hosts))
    problems = policy.get_open_problems(api, list(hosts))
    state_file = Path(state_file)
    if not state_file.parent.is_dir():
        raise RuntimeError('Missing state directory: ' + str(state_file.parent))
    if not live:
        print('READ_ONLY: SMTP', smtp['host'], smtp['port'], 'Windows hosts', len(hosts),
              'configured routes', sum(bool(x['recipients']) for x in policies.values()))
        return
    with closing(sqlite3.connect(state_file, timeout=30)) as db:
        ensure_state(db)
        cursor = get_setting(db, 'cursor')
        if cursor is None:
            latest = policy.get_latest_eventid(api, list(hosts))
            with db:
                set_setting(db, 'cursor', latest)
                set_setting(db, 'baseline_at', now)
            print(f'LIVE_BASELINE_CREATED cursor={latest} open_problems={len(problems)}; '
                  'no historical messages queued or sent')
            return
        events, new_cursor = policy.poll_new_events(api, list(hosts), int(cursor))
        with db:
            new_candidates = 0
            for e in events:
                if str(e.get('value')) != '1' or int(e.get('severity', 0)) < 4:
                    continue
                tr = triggers.get(str(e.get('objectid')))
                if tr is None:
                    continue
                db.execute('''INSERT OR IGNORE INTO candidates
                    (eventid,hostid,kind,name,severity,born) VALUES(?,?,?,?,?,?)''',
                    (str(e['eventid']),tr['hostid'],tr['kind'],str(e.get('name') or ''),
                     int(e['severity']),int(e['clock'])))
                new_candidates += 1
            enqueued, waiting, blocked, paused = schedule(db, hosts, policies, problems, triggers, now)
            set_setting(db, 'cursor', new_cursor)
        current, suppressed = policy.active_candidate_snapshot(db, problems, triggers, policies)
        sent, failed, cancelled = deliver(db, smtp, portal_db, settings_mod, hosts,
                                         policies, current, suppressed, now, smtp_factory)
        print(f'LIVE: hosts={len(hosts)} project_hosts={len(routes)} events={len(events)} '
              f'candidates={new_candidates} queued={enqueued} waiting={waiting} '
              f'blocked={blocked} maintenance={paused} accepted={sent} retries={failed} '
              f'cancelled={cancelled} cursor={new_cursor}')


def main():
    parser = argparse.ArgumentParser(description='LIVE Zabbix incident mailer; --live required to write or send')
    parser.add_argument('--live', action='store_true', help='ENABLE actual SMTP and stateful collection')
    parser.add_argument('--env', default=policy.DEFAULT_ENV)
    parser.add_argument('--portal-db', default=policy.DEFAULT_PORTAL_DB)
    parser.add_argument('--portal-code-dir', default=policy.DEFAULT_PORTAL_CODE)
    parser.add_argument('--state-db', default=STATE_DB)
    parser.add_argument('--template-id', default='10081')
    a = parser.parse_args()
    config = {}
    try:
        config = policy.read_env(a.env)
    except PermissionError:
        pass  # systemd EnvironmentFile is read by PID1 for non-root service.
    # systemd injects variables when run as the unprivileged maintenance-portal user.
    config.update({k: v for k,v in os.environ.items() if k.startswith('ZABBIX_') or k=='PORTAL_PROJECT_RBAC'})
    if config.get('PORTAL_PROJECT_RBAC') != '1':
        raise RuntimeError('PORTAL_PROJECT_RBAC must stay enabled')
    token = config.get('ZABBIX_API_TOKEN') or config.get('ZABBIX_TOKEN')
    if not token:
        raise RuntimeError('Missing Zabbix API token')
    url = config.get('ZABBIX_API_URL') or 'http://127.0.0.1/zabbix/api_jsonrpc.php'
    if not (url.startswith('https://') or url.startswith('http://127.0.0.1/')):
        raise RuntimeError('Zabbix API must use HTTPS or loopback')
    api = policy.Zabbix(url, token)
    if not a.live:
        run(api, a.portal_db, a.state_db, a.template_id, a.portal_code_dir, int(time.time()), False)
        return
    state_db = Path(a.state_db)
    if not state_db.parent.is_dir():
        raise RuntimeError('State directory not present; configure systemd StateDirectory')
    with open(str(state_db) + '.lock', 'a+', encoding='utf8') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(api, a.portal_db, state_db, a.template_id, a.portal_code_dir, int(time.time()))

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, sqlite3.Error, requests.RequestException,
            smtplib.SMTPException, BlockingIOError) as exc:
        print(f'ERROR: {type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(1)
