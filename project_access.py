"""Project-scoped AD security groups, live directory authorization and SQLite mapping.
This module never modifies Active Directory or Zabbix.
"""
import json
import os
import re
import sqlite3
import ssl
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

from fastapi import HTTPException
from ldap3 import Server, Connection, Tls, SIMPLE, SUBTREE
from ldap3.utils.conv import escape_filter_chars

ROLE_GROUPS = {
    'admin': 'GG_Zabbix_Maintenance_Admins',
    'operator': 'GG_Zabbix_Maintenance_Operators',
    'viewer': 'GG_Zabbix_Maintenance_Viewers',
}
UPN_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+$')


def enabled():
    return os.getenv('PORTAL_PROJECT_RBAC', '0') == '1'


@contextmanager
def _connect_db(path):
    db = sqlite3.connect(path, timeout=15)
    try:
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('PRAGMA foreign_keys=ON')
        db.row_factory = sqlite3.Row
        with db:
            yield db
    finally:
        db.close()


def ensure_schema(path):
    with _connect_db(path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS mp_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            created_utc TEXT NOT NULL,
            created_by TEXT NOT NULL
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS mp_project_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES mp_projects(id) ON DELETE RESTRICT,
            group_sid TEXT NOT NULL,
            sam_name TEXT NOT NULL,
            cn TEXT NOT NULL,
            group_dn TEXT NOT NULL,
            created_utc TEXT NOT NULL,
            UNIQUE(project_id,group_sid)
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS mp_project_groups_sid ON mp_project_groups(group_sid)')
        db.execute('''CREATE TABLE IF NOT EXISTS mp_project_hosts (
            host_id TEXT PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES mp_projects(id) ON DELETE RESTRICT,
            added_utc TEXT NOT NULL
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS mp_project_hosts_project ON mp_project_hosts(project_id)')
        db.execute('''CREATE TABLE IF NOT EXISTS mp_project_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_utc TEXT NOT NULL,
            actor TEXT NOT NULL,
            operation TEXT NOT NULL,
            details TEXT NOT NULL
        )''')



def refuse_unsafe_disable(path):
    """Avoid exposing reserved project hosts if someone disables project RBAC."""
    if enabled():
        return
    with _connect_db(path) as db:
        count = db.execute('SELECT count(*) FROM mp_project_hosts').fetchone()[0]
    if count:
        raise RuntimeError('REFUSING STARTUP: project hosts exist but PORTAL_PROJECT_RBAC=0. '
                           'Keep segregation enabled, or explicitly deallocate projects first.')


def _now():
    return datetime.now(timezone.utc).isoformat()


def _log(db, actor, operation, details):
    db.execute('INSERT INTO mp_project_audit(created_utc,actor,operation,details) VALUES (?,?,?,?)',
               (_now(), actor, operation, json.dumps(details, ensure_ascii=False, sort_keys=True)))


def _directory_secret():
    credential_dir = os.getenv('CREDENTIALS_DIRECTORY', '').strip()
    if credential_dir:
        path = Path(credential_dir) / 'ad_bind_password'
        try:
            return path.read_text(encoding='utf-8').rstrip('\r\n')
        except OSError as exc:
            raise RuntimeError('AD service credential unavailable') from exc
    # For integration tests and manual non-systemd runs only.
    return os.getenv('AD_BIND_PASSWORD', '')


def _ldap_connection():
    host = os.environ['AD_LDAPS_HOST']
    ca = os.environ.get('AD_CA_FILE', '/etc/maintenance-portal/certs/ad-root-ca.pem')
    username = os.environ['AD_BIND_USER']
    password = _directory_secret()
    if not password:
        raise RuntimeError('Missing LDAP bind credential')
    server = Server(host, port=636, use_ssl=True, connect_timeout=7,
                    tls=Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca,
                            version=ssl.PROTOCOL_TLS_CLIENT))
    conn = Connection(server, user=username, password=password,
                      authentication=SIMPLE, auto_bind=False, receive_timeout=10,
                      raise_exceptions=True)
    if not conn.bind():
        raise RuntimeError('LDAP service bind rejected')
    return conn


def _entry_value(entry, field):
    value = getattr(entry, field, None)
    return str(value.value) if value is not None and value.value is not None else ''


def _is_security_group(entry):
    try:
        return bool(int(_entry_value(entry, 'groupType')) & 0x80000000)
    except (ValueError, TypeError):
        return False


def _safe_upn(username):
    if not UPN_RE.fullmatch(username):
        raise HTTPException(403, 'Unsupported AD identity')
    suffix = os.getenv('AD_UPN_SUFFIX', '').strip()
    if suffix and username.rsplit('@', 1)[1].lower() != suffix.lower():
        raise HTTPException(403, 'Unsupported AD identity')
    return escape_filter_chars(username)


def _member_groups(username):
    """Nested security group SIDs and SAM names, resolved live at every HTTP request."""
    try:
        conn = _ldap_connection()
        try:
            base = os.environ['AD_BASE_DN']
            conn.search(base,
                        f'(&(objectCategory=person)(objectClass=user)(userPrincipalName={_safe_upn(username)})'
                        '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                        SUBTREE, attributes=['distinguishedName'], size_limit=2)
            if len(conn.entries) != 1:
                raise HTTPException(403, 'AD account unavailable')
            dn = str(conn.entries[0].entry_dn)
            expression = ('(&(objectCategory=group)'
                          f'(member:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)}))')
            groups = []
            for e in conn.extend.standard.paged_search(
                search_base=base, search_filter=expression, search_scope=SUBTREE,
                attributes=['objectSid', 'sAMAccountName', 'groupType'],
                paged_size=200, generator=True
            ):
                if e.get('type') != 'searchResEntry':
                    continue
                attrs = e.get('attributes', {})
                try:
                    gtype = int(attrs.get('groupType', 0))
                except (TypeError, ValueError):
                    continue
                if not (gtype & 0x80000000):
                    continue
                sid = str(attrs.get('objectSid', '') or '')
                sam = str(attrs.get('sAMAccountName', '') or '').lower()
                if sid.startswith('S-1-') and sam:
                    groups.append((sid, sam))
            return groups
        finally:
            conn.unbind()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, 'Directory authorization temporarily unavailable') from exc


def _scope_from_groups(db_path, username, groups):
    sam = {name for _, name in groups}
    sid = {sid for sid, _ in groups}
    if ROLE_GROUPS['admin'].lower() in sam:
        return {'name': username, 'role': 'admin', 'scope': 'admin', 'project_ids': []}
    with _connect_db(db_path) as db:
        matches = db.execute('SELECT DISTINCT project_id,group_sid FROM mp_project_groups').fetchall()
    project_ids = sorted({int(r['project_id']) for r in matches if r['group_sid'] in sid})
    if project_ids:
        return {'name': username, 'role': 'operator', 'scope': 'project', 'project_ids': project_ids}
    if ROLE_GROUPS['operator'].lower() in sam:
        return {'name': username, 'role': 'operator', 'scope': 'general', 'project_ids': []}
    if ROLE_GROUPS['viewer'].lower() in sam:
        return {'name': username, 'role': 'viewer', 'scope': 'general', 'project_ids': []}
    raise HTTPException(403, 'No active portal access group')


def live_rights(db_path, username):
    return _scope_from_groups(db_path, username, _member_groups(username))


def identity(db_path, request, session_reader):
    if hasattr(request.state, 'mp_resolved_identity'):
        return request.state.mp_resolved_identity
    session = session_reader(db_path, request)
    if not enabled():
        user = dict(session, scope='legacy', project_ids=[])
    else:
        user = dict(session, **live_rights(db_path, session['name']))
    request.state.mp_resolved_identity = user
    return user


def filter_hosts(db_path, user, all_hosts):
    if not enabled() or user['scope'] == 'admin':
        return all_hosts
    with _connect_db(db_path) as db:
        if user['scope'] == 'project':
            projects = user.get('project_ids', [])
            if not projects:
                return {}
            placeholders = ','.join('?' for _ in projects)
            ids = {str(r[0]) for r in db.execute(
                f'SELECT host_id FROM mp_project_hosts WHERE project_id IN ({placeholders})', projects)}
        else:
            reserved = {str(r[0]) for r in db.execute('SELECT host_id FROM mp_project_hosts')}
            return {hid: host for hid, host in all_hosts.items() if hid not in reserved}
    return {hid: host for hid, host in all_hosts.items() if hid in ids}


def find_ad_group(name):
    """Resolve an existing AD security group by exact CN or sAMAccountName."""
    name = name.strip()
    if not 2 <= len(name) <= 120 or any(ch in name for ch in '\r\n\x00'):
        raise HTTPException(422, 'Invalid AD group name')
    try:
        conn = _ldap_connection()
        try:
            val = escape_filter_chars(name)
            conn.search(os.environ['AD_BASE_DN'],
                        f'(&(objectCategory=group)(|(cn={val})(sAMAccountName={val})))',
                        SUBTREE, attributes=['cn', 'sAMAccountName', 'objectSid', 'groupType'],
                        size_limit=3)
            matches = [entry for entry in conn.entries if _is_security_group(entry)]
            if not matches:
                raise HTTPException(404, 'Security group not found in AD')
            sids = {_entry_value(entry, 'objectSid') for entry in matches}
            if len(sids) != 1:
                raise HTTPException(409, 'Multiple AD groups match; use exact sAMAccountName')
            entry = matches[0]
            sam = _entry_value(entry, 'sAMAccountName')
            if sam.lower() in {v.lower() for v in ROLE_GROUPS.values()}:
                raise HTTPException(422, 'Portal base role group cannot be a project group')
            sid = _entry_value(entry, 'objectSid')
            if not sid.startswith('S-1-'):
                raise HTTPException(503, 'AD did not return a valid group SID')
            return {'sid': sid, 'sam': sam, 'cn': _entry_value(entry, 'cn'),
                    'dn': str(entry.entry_dn)}
        finally:
            conn.unbind()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, 'Directory group lookup unavailable') from exc


def _assert_project(db, project_id):
    if not db.execute('SELECT 1 FROM mp_projects WHERE id=?', (project_id,)).fetchone():
        raise HTTPException(404, 'Project not found')


def create_project(path, actor, name):
    name = ' '.join(name.split())
    if not 3 <= len(name) <= 100:
        raise HTTPException(422, 'Project name length must be 3..100')
    with _connect_db(path) as db:
        try:
            cur = db.execute('INSERT INTO mp_projects(name,created_utc,created_by) VALUES(?,?,?)',
                             (name, _now(), actor))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, 'Project name already exists') from exc
        project_id = cur.lastrowid
        _log(db, actor, 'project.create', {'project_id': project_id, 'name': name})
    return project_id


def add_group(path, actor, project_id, group):
    with _connect_db(path) as db:
        _assert_project(db, project_id)
        try:
            db.execute('''INSERT INTO mp_project_groups(project_id,group_sid,sam_name,cn,group_dn,created_utc)
                          VALUES(?,?,?,?,?,?)''',
                       (project_id, group['sid'], group['sam'], group['cn'], group['dn'], _now()))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, 'AD group already assigned to this project') from exc
        _log(db, actor, 'group.add', {'project_id': project_id, 'group_sid': group['sid'],
                                     'group': group['sam']})


def remove_group(path, actor, project_id, group_id):
    with _connect_db(path) as db:
        _assert_project(db, project_id)
        row = db.execute('SELECT * FROM mp_project_groups WHERE id=? AND project_id=?',
                         (group_id, project_id)).fetchone()
        if not row:
            raise HTTPException(404, 'Group assignment not found')
        n_groups = db.execute('SELECT count(*) FROM mp_project_groups WHERE project_id=?',
                              (project_id,)).fetchone()[0]
        n_hosts = db.execute('SELECT count(*) FROM mp_project_hosts WHERE project_id=?',
                             (project_id,)).fetchone()[0]
        if n_groups == 1 and n_hosts:
            raise HTTPException(409, 'Cannot remove last AD group while project owns hosts')
        db.execute('DELETE FROM mp_project_groups WHERE id=?', (group_id,))
        _log(db, actor, 'group.remove', {'project_id': project_id, 'group_sid': row['group_sid']})


def assign_host(path, actor, project_id, host_id):
    with _connect_db(path) as db:
        db.execute('BEGIN IMMEDIATE')
        _assert_project(db, project_id)
        count = db.execute('SELECT count(*) FROM mp_project_groups WHERE project_id=?',
                           (project_id,)).fetchone()[0]
        if not count:
            raise HTTPException(409, 'Assign an AD group before assigning hosts')
        try:
            db.execute('INSERT INTO mp_project_hosts(host_id,project_id,added_utc) VALUES(?,?,?)',
                       (host_id, project_id, _now()))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, 'Host already assigned to a project') from exc
        _log(db, actor, 'host.assign', {'project_id': project_id, 'host_id': host_id})


def release_host(path, actor, project_id, host_id):
    with _connect_db(path) as db:
        db.execute('BEGIN IMMEDIATE')
        _assert_project(db, project_id)
        cur = db.execute('DELETE FROM mp_project_hosts WHERE host_id=? AND project_id=?',
                         (host_id, project_id))
        if cur.rowcount != 1:
            raise HTTPException(404, 'Host not assigned to this project')
        _log(db, actor, 'host.release_to_general', {'project_id': project_id, 'host_id': host_id})


def move_host(path, actor, host_id, target_project_id):
    with _connect_db(path) as db:
        db.execute('BEGIN IMMEDIATE')
        _assert_project(db, target_project_id)
        num_groups = db.execute('SELECT count(*) FROM mp_project_groups WHERE project_id=?',
                                (target_project_id,)).fetchone()[0]
        if not num_groups:
            raise HTTPException(409, 'Target project has no AD group')
        prev = db.execute('SELECT project_id FROM mp_project_hosts WHERE host_id=?',
                          (host_id,)).fetchone()
        if not prev:
            raise HTTPException(404, 'Host is not assigned to a project')
        if int(prev[0]) == int(target_project_id):
            raise HTTPException(409, 'Host already belongs to target project')
        db.execute('UPDATE mp_project_hosts SET project_id=?,added_utc=? WHERE host_id=?',
                   (target_project_id, _now(), host_id))
        _log(db, actor, 'host.move', {'host_id': host_id, 'from': prev[0],
                                      'to': target_project_id})


def delete_empty_project(path, actor, project_id):
    with _connect_db(path) as db:
        db.execute('BEGIN IMMEDIATE')
        _assert_project(db, project_id)
        if db.execute('SELECT 1 FROM mp_project_hosts WHERE project_id=?', (project_id,)).fetchone():
            raise HTTPException(409, 'Release or move project hosts before deleting project')
        if db.execute('SELECT 1 FROM mp_project_groups WHERE project_id=?', (project_id,)).fetchone():
            raise HTTPException(409, 'Remove project AD groups before deleting project')
        db.execute('DELETE FROM mp_projects WHERE id=?', (project_id,))
        _log(db, actor, 'project.delete', {'project_id': project_id})


def admin_snapshot(path, all_hosts):
    with _connect_db(path) as db:
        projects = [dict(row) for row in db.execute('SELECT * FROM mp_projects ORDER BY name')]
        groups = [dict(row) for row in db.execute('SELECT * FROM mp_project_groups ORDER BY sam_name')]
        assigned = [dict(row) for row in db.execute('SELECT * FROM mp_project_hosts ORDER BY host_id')]
        history = [dict(row) for row in db.execute('SELECT * FROM mp_project_audit ORDER BY id DESC LIMIT 30')]
    for project in projects:
        project['groups'] = [g for g in groups if g['project_id'] == project['id']]
        project['hosts'] = [{**h, 'name': all_hosts.get(h['host_id'], {}).get('name',
                                  f"{h['host_id']} (not currently in enabled Windows scope)")}
                            for h in assigned if h['project_id'] == project['id']]
    occupied = {row['host_id'] for row in assigned}
    unassigned = sorted([h for hid, h in all_hosts.items() if hid not in occupied],
                        key=lambda h: h['name'].casefold())
    return {'projects': projects, 'unassigned': unassigned, 'history': history,
            'assigned': assigned}
