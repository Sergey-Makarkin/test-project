"""Email Alerting settings for Maintenance Portal.

Configuration storage only. No SMTP, no Zabbix API writes, no scheduler.
Project membership remains owned by project_access.py.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import re
import sqlite3
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63}\Z")
MAX_ADDRESSES = 30
MAX_RULES = 5000


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@contextmanager
def connect(path, *, read_only=False):
    if read_only:
        path = Path(path).resolve()
        db = sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True, timeout=15)
    else:
        db = sqlite3.connect(str(path), timeout=15)
    try:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('PRAGMA foreign_keys=ON')
        if read_only:
            db.execute('PRAGMA query_only=ON')
        yield db
    finally:
        db.close()


def ensure_schema(path):
    """Add only mp_alert_* tables; idempotent. Never modify existing project rows."""
    with connect(path) as db, db:
        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_general (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            recipients_json TEXT NOT NULL DEFAULT '[]',
            updated_utc TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_project_recipients (
            project_id INTEGER PRIMARY KEY REFERENCES mp_projects(id) ON DELETE CASCADE,
            recipients_json TEXT NOT NULL DEFAULT '[]',
            updated_utc TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_service_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL CHECK(scope IN ('global', 'project', 'host')),
            project_id INTEGER REFERENCES mp_projects(id) ON DELETE CASCADE,
            host_id TEXT,
            service_name TEXT NOT NULL COLLATE NOCASE,
            mode TEXT NOT NULL CHECK(mode IN ('critical', 'exclude')),
            severity INTEGER NOT NULL CHECK(severity IN (4, 5)),
            created_utc TEXT NOT NULL,
            created_by TEXT NOT NULL,
            CHECK(
                (scope = 'global' AND project_id IS NULL AND host_id IS NULL) OR
                (scope = 'project' AND project_id IS NOT NULL AND host_id IS NULL) OR
                (scope = 'host' AND project_id IS NULL AND host_id IS NOT NULL)
            )
        )''')
        db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS mp_alert_rule_global_unique
            ON mp_alert_service_rules(service_name) WHERE scope='global' ''')
        db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS mp_alert_rule_project_unique
            ON mp_alert_service_rules(project_id, service_name) WHERE scope='project' ''')
        db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS mp_alert_rule_host_unique
            ON mp_alert_service_rules(host_id, service_name) WHERE scope='host' ''')
        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_utc TEXT NOT NULL,
            actor TEXT NOT NULL,
            operation TEXT NOT NULL,
            details TEXT NOT NULL
        )''')
        db.execute('''INSERT OR IGNORE INTO mp_alert_general
            (id,recipients_json,updated_utc,updated_by) VALUES(1,'[]',?, 'system')''', (utc_now(),))


def normalize_recipients(raw):
    """Allow bare mailbox addresses only, never display names or CRLF headers."""
    if len(raw) > 6000:
        raise ValueError('Recipient list is too long')
    parts = [s.strip() for s in re.split(r'[,;\s]+', raw) if s.strip()]
    if len(parts) > MAX_ADDRESSES:
        raise ValueError(f'Maximum {MAX_ADDRESSES} recipients per destination')
    if any(not EMAIL_RE.fullmatch(item) or '..' in item for item in parts):
        raise ValueError('Use plain mailbox addresses, separated by commas or newlines')
    # A single address cannot contain CR or LF: split and validation prevent injection.
    unique = {}
    for address in parts:
        unique[address.lower()] = address
    return sorted(unique.values(), key=str.lower)


def service_name_validate(name):
    name = str(name).strip()
    if not 1 <= len(name) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError('Invalid Windows service short name (1..128 printable characters)')
    if '/' in name or '\\' in name or '*' in name or '?' in name:
        raise ValueError('Use an exact Windows service short name, not a glob/regular expression')
    return name


def audit(db, actor, operation, details):
    db.execute('INSERT INTO mp_alert_audit(created_utc,actor,operation,details) VALUES(?,?,?,?)',
               (utc_now(), actor, operation, json.dumps(details, ensure_ascii=False, sort_keys=True)))


def set_general_recipients(path, actor, raw):
    recips = normalize_recipients(raw)
    with connect(path) as db, db:
        db.execute('UPDATE mp_alert_general SET recipients_json=?,updated_utc=?,updated_by=? WHERE id=1',
                   (json.dumps(recips), utc_now(), actor))
        audit(db, actor, 'recipients.general', {'recipients': recips})
    return recips


def set_project_recipients(path, actor, project_id, raw):
    recips = normalize_recipients(raw)
    with connect(path) as db, db:
        if not db.execute('SELECT 1 FROM mp_projects WHERE id=?', (int(project_id),)).fetchone():
            raise ValueError('Project does not exist')
        db.execute('''INSERT INTO mp_alert_project_recipients
           (project_id,recipients_json,updated_utc,updated_by) VALUES(?,?,?,?)
           ON CONFLICT(project_id) DO UPDATE SET recipients_json=excluded.recipients_json,
              updated_utc=excluded.updated_utc,updated_by=excluded.updated_by''',
           (int(project_id), json.dumps(recips), utc_now(), actor))
        audit(db, actor, 'recipients.project', {'project_id': int(project_id), 'recipients': recips})
    return recips


def add_or_update_rule(path, actor, *, scope, project_id=None, host_id=None,
                       service_name, mode, severity=4, allowed_hostids=None):
    service_name = service_name_validate(service_name)
    if scope not in ('global', 'project', 'host'):
        raise ValueError('Invalid rule scope')
    if mode not in ('critical', 'exclude') or int(severity) not in (4, 5):
        raise ValueError('Invalid mode or severity')
    if scope == 'global' and (project_id is not None or host_id is not None):
        raise ValueError('Global rule cannot reference a project or host')
    if scope == 'project' and (project_id is None or host_id is not None):
        raise ValueError('Project scope requires project_id only')
    if scope == 'host' and (not host_id or project_id is not None):
        raise ValueError('Host scope requires host_id only')
    if scope == 'host':
        host_id = str(host_id)
        if not host_id.isdecimal() or allowed_hostids is None or host_id not in allowed_hostids:
            raise ValueError('Host must be an enabled, known Windows host')
    if scope == 'project':
        project_id = int(project_id)
    with connect(path) as db, db:
        if scope == 'project' and not db.execute('SELECT 1 FROM mp_projects WHERE id=?',
                                               (project_id,)).fetchone():
            raise ValueError('Project not found')
        existing = db.execute('''SELECT id FROM mp_alert_service_rules WHERE scope=?
             AND ((? IS NULL AND project_id IS NULL) OR project_id=?)
             AND ((? IS NULL AND host_id IS NULL) OR host_id=?)
             AND service_name=? COLLATE NOCASE''',
             (scope, project_id, project_id, host_id, host_id, service_name)).fetchone()
        if existing:
            db.execute('UPDATE mp_alert_service_rules SET mode=?,severity=?,created_utc=?,created_by=? WHERE id=?',
                       (mode, int(severity), utc_now(), actor, existing['id']))
            rule_id = existing['id']
        else:
            if db.execute('SELECT count(*) FROM mp_alert_service_rules').fetchone()[0] >= MAX_RULES:
                raise ValueError('Maximum rule count reached')
            cur = db.execute('''INSERT INTO mp_alert_service_rules
                (scope,project_id,host_id,service_name,mode,severity,created_utc,created_by)
                VALUES(?,?,?,?,?,?,?,?)''',
                (scope, project_id, host_id, service_name, mode, int(severity), utc_now(), actor))
            rule_id = cur.lastrowid
        audit(db, actor, 'rule.upsert', {'rule_id': rule_id, 'scope': scope,
              'project_id': project_id, 'host_id': host_id,
              'service_name': service_name, 'mode': mode, 'severity': int(severity)})
    return rule_id


def remove_rule(path, actor, rule_id):
    with connect(path) as db, db:
        row = db.execute('SELECT scope,project_id,host_id,service_name FROM mp_alert_service_rules WHERE id=?',
                         (int(rule_id),)).fetchone()
        if row is None:
            raise ValueError('Alert rule not found')
        db.execute('DELETE FROM mp_alert_service_rules WHERE id=?', (int(rule_id),))
        audit(db, actor, 'rule.remove', {'rule_id': int(rule_id), **dict(row)})


def snapshot(path):
    with connect(path, read_only=True) as db:
        projects = [dict(row) for row in db.execute('''SELECT p.id,p.name,
            COALESCE(r.recipients_json,'[]') AS recipients_json
            FROM mp_projects p LEFT JOIN mp_alert_project_recipients r ON r.project_id=p.id
            ORDER BY p.name COLLATE NOCASE''')]
        for p in projects:
            p['recipients'] = json.loads(p['recipients_json'])
            p['recipients_text'] = ', '.join(p['recipients'])
        general = json.loads(db.execute('SELECT recipients_json FROM mp_alert_general WHERE id=1').fetchone()[0])
        rules = [dict(row) for row in db.execute('''SELECT r.id,r.scope,r.project_id,r.host_id,
            r.service_name,r.mode,r.severity,p.name AS project_name
            FROM mp_alert_service_rules r LEFT JOIN mp_projects p ON p.id=r.project_id
            ORDER BY CASE r.scope WHEN 'global' THEN 0 WHEN 'project' THEN 1 ELSE 2 END,
                     p.name COLLATE NOCASE,r.host_id,r.service_name COLLATE NOCASE''')]
        audit_rows = [dict(row) for row in db.execute('''SELECT created_utc,actor,operation,details
            FROM mp_alert_audit ORDER BY id DESC LIMIT 20''')]
    return {'general_recipients': general, 'general_recipients_text': ', '.join(general),
            'projects': projects, 'rules': rules, 'history': audit_rows}


def effective_for_host(path, host_id):
    """Read-only deterministic policy. Caller must first validate that host is in Windows scope.

    Missing project recipients must NEVER fall back to general recipients.
    No service regex/glob matching: short names are exact and case-insensitive.
    """
    host_id = str(host_id)
    with connect(path, read_only=True) as db:
        project = db.execute('''SELECT p.id,p.name FROM mp_project_hosts h
                    JOIN mp_projects p ON p.id=h.project_id WHERE h.host_id=?''', (host_id,)).fetchone()
        project_id = project['id'] if project else None
        if project is None and db.execute('SELECT 1 FROM mp_project_hosts WHERE host_id=?', (host_id,)).fetchone():
            raise RuntimeError('Orphan project assignment, refusing route')
        if project:
            rr = db.execute('SELECT recipients_json FROM mp_alert_project_recipients WHERE project_id=?',
                            (project_id,)).fetchone()
            recipients = json.loads(rr[0]) if rr else []
        else:
            recipients = json.loads(db.execute('SELECT recipients_json FROM mp_alert_general WHERE id=1').fetchone()[0])
        # Winner by specificity: global -> project -> host. Exclusion at any scope can be
        # overridden by an explicit critical rule at a more specific scope.
        rules = db.execute('''SELECT scope,service_name,mode,severity FROM mp_alert_service_rules
                   WHERE scope='global' OR (scope='project' AND project_id=?)
                      OR (scope='host' AND host_id=?)
                   ORDER BY CASE scope WHEN 'global' THEN 0 WHEN 'project' THEN 1 ELSE 2 END, id''',
                   (project_id, host_id)).fetchall()
        matched = {}
        for row in rules:
            key = row['service_name'].lower()
            if row['mode'] == 'exclude':
                matched.pop(key, None)
            else:
                matched[key] = {'name': row['service_name'], 'severity': row['severity']}
    return {'host_id': host_id, 'scope': 'project' if project else 'general',
            'project_id': project_id, 'project_name': project['name'] if project else None,
            'recipients': recipients, 'route_configured': bool(recipients),
            'critical_services': sorted(matched.values(), key=lambda r: r['name'].lower())}


def build_lld_regex(critical_services):
    """Preview only, not applied to Zabbix. Exact names, PCRE case-insensitive."""
    names = [item['name'] for item in critical_services]
    if not names:
        return '^$'
    regex = '(?i)^(?:' + '|'.join(re.escape(n) for n in sorted(names, key=str.lower)) + ')$'
    if len(regex) > 4096:
        raise ValueError('LLD regex too long for safe automatic application')
    return regex
