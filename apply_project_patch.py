#!/usr/bin/env python3
"""Apply a guarded, minimal RBAC patch to an existing Maintenance Portal.
No AD/Zabbix calls; no changes to existing maintenance records. Idempotent.
Run from /opt/maintenance-portal-demo after taking an offline backup.
"""
from pathlib import Path
import ast
import difflib
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parent
APP = ROOT / 'app.py'
INDEX = ROOT / 'templates' / 'index.html'


def require_replace(value, old, new, label, count=1):
    observed = value.count(old)
    if observed != count:
        raise RuntimeError(f'{label}: expected {count} occurrence(s), found {observed}; nothing changed')
    return value.replace(old, new)


def build_app(original):
    if 'project_admin.install_admin_routes(' in original:
        raise RuntimeError('Project RBAC appears to be already installed; aborting')
    source = original
    source = require_replace(source,
        'from ad_auth import authenticate\n',
        'from ad_auth import authenticate\nimport project_access\nimport project_admin\n',
        'new imports')
    source = require_replace(source,
        'ensure_tables(DB)\n',
        'ensure_tables(DB)\nproject_access.ensure_schema(DB)\nproject_access.refuse_unsafe_disable(DB)\n',
        'SQLite migration')
    source = require_replace(source,
        'def identity(request):\n    return session_from_request(DB, request)\n',
        'def identity(request):\n    return project_access.identity(DB, request, session_from_request)\n',
        'live AD authorization')
    source = require_replace(source,
        '''    if not result.authenticated or not result.authorized:
        record_login_failure(DB, username)
        log_auth(DB, 'login', username, 'DENIED')
        raise HTTPException(401, 'Invalid credentials or insufficient group membership')
    clear_login_failures(DB, username)
    token = create_session(DB, username, result.role)
''',
        '''    if not result.authenticated:
        record_login_failure(DB, username)
        log_auth(DB, 'login', username, 'DENIED')
        raise HTTPException(401, 'Invalid credentials or insufficient group membership')
    if project_access.enabled():
        try:
            role = project_access.live_rights(DB, username)['role']
        except HTTPException as exc:
            if exc.status_code == 403:
                record_login_failure(DB, username)
                log_auth(DB, 'login', username, 'DENIED')
                raise HTTPException(401, 'Invalid credentials or insufficient group membership')
            log_auth(DB, 'login', username, 'ERROR')
            raise
    else:
        if not result.authorized:
            record_login_failure(DB, username)
            log_auth(DB, 'login', username, 'DENIED')
            raise HTTPException(401, 'Invalid credentials or insufficient group membership')
        role = result.role
    clear_login_failures(DB, username)
    token = create_session(DB, username, role)
''',
        'allow project-only logins')
    source = require_replace(source,
        '\ndef validate(user, host_id, duration, reason, hosts, start_delay=0):',
        '''\ndef visible_hosts(user):
    """Enforce project scoping for every list, review and execute endpoint."""
    return project_access.filter_hosts(DB, user, allowed_hosts())


def validate(user, host_id, duration, reason, hosts, start_delay=0):''',
        'enforced Windows host scope')
    source = require_replace(source,
        """        and host_id in allowed_hosts()
    )


def zabbix_create""",
        """        and host_id in visible_hosts(user)
    )


def zabbix_create""",
        'live create preview authorization')
    source = require_replace(source,
        'def zabbix_create(params, *, live=False):',
        'def zabbix_create(params, *, live=False, user=None):',
        'live write caller identity')
    source = require_replace(source,
        """            or host_id not in allowed_hosts()
            or int(params['timeperiods'][0]['period'])""",
        """            or host_id not in allowed_hosts()
            or (project_access.enabled() and (user is None or host_id not in visible_hosts(user)))
            or int(params['timeperiods'][0]['period'])""",
        'enforce project scope at Zabbix write')
    source = require_replace(source,
        """            or maintenance['host_id'] not in allowed_hosts()):""",
        """            or maintenance['host_id'] not in visible_hosts(user)):""",
        'enforce project scope at maintenance management')
    source = require_replace(source,
        'result = zabbix_create(params, live=live)',
        'result = zabbix_create(params, live=live, user=user)',
        'pass identity to Zabbix write')
    source = require_replace(source, '    hosts = allowed_hosts()\n',
                             '    hosts = visible_hosts(user)\n',
                             'route host scoping', count=5)
    source = require_replace(source,
        '''    with db_connect() as db:
        rows = db.execute("""SELECT created_at,actor,host_id,duration_minutes,outcome,request_id
                             FROM audit ORDER BY id DESC LIMIT 10""").fetchall()
''',
        '''    with db_connect() as db:
        if user['scope'] == 'admin' or not project_access.enabled():
            rows = db.execute("""SELECT created_at,actor,host_id,duration_minutes,outcome,request_id
                                 FROM audit ORDER BY id DESC LIMIT 10""").fetchall()
        elif hosts:
            host_ids = list(hosts)
            placeholders = ','.join('?' for _ in host_ids)
            rows = db.execute(
                f"""SELECT created_at,actor,host_id,duration_minutes,outcome,request_id
                     FROM audit WHERE host_id IN ({placeholders}) ORDER BY id DESC LIMIT 10""",
                host_ids).fetchall()
        else:
            rows = []
''',
        'scope audit log')
    source += '''\n\n# Additional administration endpoints. Existing Maintenance routes remain unchanged.\nproject_admin.install_admin_routes(\n    app, DB, templates, identity, check_csrf, allowed_hosts\n)\n'''
    ast.parse(source, filename=str(APP))
    return source


def build_index(original):
    if 'href="/admin"' in original:
        raise RuntimeError('Admin link already present; aborting')
    return require_replace(original, '<form method="post" action="/logout"',
        '''{% if user.role == 'admin' %}
      <a href="/admin" class="button secondary" style="margin:0">Administration</a>
    {% endif %}
    <form method="post" action="/logout"''', 'Admin menu link')


def main():
    if not APP.exists() or not INDEX.exists():
        raise SystemExit('Run in project root with existing app.py and templates/index.html')
    orig_app, orig_index = APP.read_text(), INDEX.read_text()
    try:
        new_app, new_index = build_app(orig_app), build_index(orig_index)
    except Exception as exc:
        raise SystemExit(f'PATCH NOT APPLIED: {exc}') from exc
    # Check templates parse and required files exist before writing anything.
    from jinja2 import Environment
    for filename in ['admin.html', 'admin_group.html']:
        path = ROOT / 'templates' / filename
        if not path.exists():
            raise SystemExit(f'PATCH NOT APPLIED: missing {path}')
        Environment().parse(path.read_text())
    if '--check' in sys.argv:
        print('PATCH CHECK: PASS (no files changed)')
        print('Planned changes: app.py and templates/index.html')
        return
    backup_app = APP.with_name('app.py.before-project-rbac')
    backup_index = INDEX.with_name('index.html.before-project-rbac')
    if backup_app.exists() or backup_index.exists():
        raise SystemExit('PATCH NOT APPLIED: existing .before-project-rbac backup; stop and inspect')
    shutil.copy2(APP, backup_app)
    shutil.copy2(INDEX, backup_index)
    APP.write_text(new_app)
    INDEX.write_text(new_index)
    print('PATCH APPLIED. Backups:', backup_app, backup_index)
    print('SQLite schema will be created on the next service startup.')


if __name__ == '__main__':
    main()
