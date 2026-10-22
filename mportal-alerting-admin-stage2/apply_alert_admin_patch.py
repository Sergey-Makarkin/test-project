#!/usr/bin/env python3
"""Guarded addon to an already-installed Project RBAC portal.
--check performs no writes. Default --apply changes app.py and templates/admin.html.
No Zabbix or SMTP operations. Alerting SQLite migration runs on next app startup.
"""
import ast
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
APP = ROOT / 'app.py'
ADMIN = ROOT / 'templates' / 'admin.html'


def replace_one(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f'{label}: required text occurs {count} times, expected once')
    return text.replace(old, new, 1)


def build_app(source):
    if 'alert_admin.install_alert_admin_routes(' in source:
        raise RuntimeError('Email alert administration already installed')
    source = replace_one(source,
         'import project_admin\n',
         'import project_admin\nimport alert_settings\nimport alert_admin\n',
         'import anchor')
    source = replace_one(source,
         'project_access.ensure_schema(DB)\n',
         'project_access.ensure_schema(DB)\nalert_settings.ensure_schema(DB)\n',
         'schema anchor')
    source = replace_one(source,
         '''project_admin.install_admin_routes(
    app, DB, templates, identity, check_csrf, allowed_hosts
)
''',
         '''project_admin.install_admin_routes(
    app, DB, templates, identity, check_csrf, allowed_hosts
)

# Email alerting settings are admin-only, with no mail delivery or Zabbix writes.
alert_admin.install_alert_admin_routes(
    app, DB, templates, identity, check_csrf, allowed_hosts
)
''',
         'admin routes anchor')
    ast.parse(source, filename=str(APP))
    return source


def build_admin(source):
    if 'href="/admin/alerting"' in source:
        raise RuntimeError('Email alert admin menu item already installed')
    return replace_one(source,
       '<a class="button secondary" style="margin:0" href="/">← Maintenance Portal</a>',
       '<a class="button secondary" style="margin:0" href="/">← Maintenance Portal</a>\n'
       '      <a class="button secondary" style="margin:0" href="/admin/alerting">Email Alerting</a>',
       'admin menu anchor')


def main():
    check = '--check' in sys.argv
    if '--apply' not in sys.argv and not check:
        raise SystemExit('Usage: apply_alert_admin_patch.py --check | --apply')
    required = [APP, ADMIN, ROOT/'alert_settings.py', ROOT/'alert_admin.py',
                ROOT/'templates'/'alerting.html']
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise SystemExit('Not installed / missing:\n' + '\n'.join(missing))
    try:
        app = build_app(APP.read_text(encoding='utf-8'))
        admin = build_admin(ADMIN.read_text(encoding='utf-8'))
        from jinja2 import Environment
        Environment().parse((ROOT/'templates'/'alerting.html').read_text(encoding='utf-8'))
        Environment().parse(admin)
        for module in (ROOT/'alert_settings.py', ROOT/'alert_admin.py'):
            ast.parse(module.read_text(encoding='utf-8'), filename=str(module))
    except Exception as exc:
        raise SystemExit(f'PATCH REFUSED, no changes: {exc}') from exc
    if check:
        print('ALERT ADMIN PATCH CHECK: PASS (no files or database changed)')
        print('Will change only app.py and templates/admin.html')
        return
    backups = [APP.with_name('app.py.before-alert-admin'),
               ADMIN.with_name('admin.html.before-alert-admin')]
    if any(p.exists() for p in backups):
        raise SystemExit('PATCH REFUSED: existing .before-alert-admin backup')
    shutil.copy2(APP, backups[0])
    shutil.copy2(ADMIN, backups[1])
    APP.write_text(app, encoding='utf-8')
    ADMIN.write_text(admin, encoding='utf-8')
    print('ALERT ADMIN PATCH APPLIED (code only). Backups:', *(str(p) for p in backups))
    print('SQLite mp_alert_* tables will be created when Maintenance Portal next starts.')


if __name__ == '__main__':
    main()
