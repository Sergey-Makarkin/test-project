#!/usr/bin/env python3
"""Add configurable SMTP From to an installed MPortal Email LIVE v1.

--check is strictly read-only. --apply patches four source files after creating
backups. Existing SMTP host, port and destination policies are preserved.
Database migration runs via alert_settings.ensure_schema() on portal startup.
"""
from __future__ import annotations
import ast
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
FILES = {
    'settings': ROOT / 'alert_settings.py',
    'admin': ROOT / 'alert_admin.py',
    'html': ROOT / 'templates' / 'alerting.html',
    'live': ROOT / 'mportal_mail_live.py',
}

def once(source: str, before: str, after: str, label: str) -> str:
    n = source.count(before)
    if n != 1:
        raise ValueError(f'{label}: expected one anchor, got {n}')
    return source.replace(before, after, 1)


def patch_settings(s):
    s = once(s, "SMTP_FROM = 'mportal@example.com'  # Fixed: not editable from Admin UI",
             "SMTP_DEFAULT_FROM = 'mportal@example.com'  # Initial value; editable in Admin UI",
             'settings default')
    old = '''def smtp_config(path):
    with connect(path, read_only=True) as db:
        row = db.execute('SELECT smtp_host,smtp_port FROM mp_alert_smtp WHERE id=1').fetchone()
        if row is None:
            raise RuntimeError('SMTP settings missing; restart Portal after patch')
        host, port = validate_smtp(row['smtp_host'], row['smtp_port'])
        return {'host': host, 'port': port, 'from': SMTP_FROM,
                'auth': False, 'starttls': False}


def set_smtp_config(path, actor, host, port):
    host, port = validate_smtp(host, port)
    with connect(path) as db, db:
        db.execute('UPDATE mp_alert_smtp SET smtp_host=?,smtp_port=?,updated_utc=?,updated_by=? WHERE id=1',
                   (host, port, utc_now(), actor))
        audit(db, actor, 'smtp.update', {'host': host, 'port': port})
    return host, port
'''
    new = '''def validate_smtp_sender(sender):
    """Only a bare valid mailbox address, never a name or header injection."""
    sender = str(sender).strip()
    if not 3 <= len(sender) <= 254 or not EMAIL_RE.fullmatch(sender) or '..' in sender:
        raise ValueError('SMTP From must be one valid plain email address')
    return sender


def smtp_config(path):
    with connect(path, read_only=True) as db:
        row = db.execute('SELECT smtp_host,smtp_port,smtp_from FROM mp_alert_smtp WHERE id=1').fetchone()
        if row is None:
            raise RuntimeError('SMTP settings missing; restart Portal after patch')
        host, port = validate_smtp(row['smtp_host'], row['smtp_port'])
        sender = validate_smtp_sender(row['smtp_from'])
        return {'host': host, 'port': port, 'from': sender,
                'auth': False, 'starttls': False}


def set_smtp_config(path, actor, host, port, smtp_from=None):
    """Update SMTP settings atomically, keep the old sender for legacy callers."""
    host, port = validate_smtp(host, port)
    with connect(path) as db, db:
        if smtp_from is None:
            row = db.execute('SELECT smtp_from FROM mp_alert_smtp WHERE id=1').fetchone()
            if row is None:
                raise RuntimeError('SMTP settings missing')
            smtp_from = row['smtp_from']
        sender = validate_smtp_sender(smtp_from)
        result = db.execute('UPDATE mp_alert_smtp SET smtp_host=?,smtp_port=?,smtp_from=?,updated_utc=?,updated_by=? WHERE id=1',
            (host, port, sender, utc_now(), actor))
        if result.rowcount != 1:
            raise RuntimeError('SMTP settings row missing')
        audit(db, actor, 'smtp.update', {'host': host, 'port': port, 'from': sender})
    return host, port
'''
    s = once(s, old, new, 'settings getter/setter')
    # This runs once on first portal startup after deployment, including old DBs.
    anchor = '''            (SMTP_DEFAULT_HOST, SMTP_DEFAULT_PORT, utc_now()))
        db.execute(\'\'\'CREATE TABLE IF NOT EXISTS mp_alert_general ('''
    replace = '''            (SMTP_DEFAULT_HOST, SMTP_DEFAULT_PORT, utc_now()))
        # Idempotent schema migration: keep existing SMTP host and port unchanged.
        smtp_columns = {r[1] for r in db.execute('PRAGMA table_info(mp_alert_smtp)')}
        if 'smtp_from' not in smtp_columns:
            db.execute('ALTER TABLE mp_alert_smtp ADD COLUMN smtp_from TEXT NOT NULL '
                       "DEFAULT 'mportal@example.com'")
        db.execute(\'\'\'CREATE TABLE IF NOT EXISTS mp_alert_general ('''
    s = once(s, anchor, replace, 'SMTP migration')
    ast.parse(s)
    return s


def patch_admin(s):
    s = once(s,
        '''    def update_smtp(request: Request, smtp_host: str = Form(...), smtp_port: int = Form(...),
                    csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.set_smtp_config, db_path, user['name'], smtp_host, smtp_port)
        return go()''',
        '''    def update_smtp(request: Request, smtp_host: str = Form(...), smtp_port: int = Form(...),
                    smtp_from: str = Form(...), csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.set_smtp_config, db_path, user['name'], smtp_host, smtp_port, smtp_from)
        return go()''',
        'admin SMTP route')
    ast.parse(s)
    return s


def patch_html(s):
    s = once(s,
             'Use a trusted internal relay; delivery and transport security depend on that server. Sender is fixed.',
             'Use a trusted internal relay; delivery and transport security depend on that server. Sender is configurable by Admin.',
             'SMTP form description')
    s = once(s,
             '''      <label>From (fixed)
        <input type="text" value="{{ smtp_from }}" disabled>
      </label>''',
             '''      <label>From (email address)
        <input type="email" name="smtp_from" maxlength="254" required value="{{ smtp_from }}" placeholder="mportal@example.com" autocomplete="off">
      </label>''',
             'SMTP From input')
    s = once(s,
             'SMTP configuration is read on every worker cycle. The sender cannot be changed here. The worker never uses AUTH/STARTTLS.',
             'SMTP host, port and From are read on every worker cycle. Changes affect new submissions; the worker never uses AUTH/STARTTLS.',
             'SMTP help text')
    from jinja2 import Environment
    Environment().parse(s)
    return s


def patch_live(s):
    s = once(s,
             "FROM_ADDR = 'mportal@example.com'",
             "FROM_ADDR = 'mportal@example.com'  # Legacy default for old one-off scripts; LIVE uses SMTP config",
             'LIVE legacy default')
    s = once(s,
             'def make_message(rec, addr, msgid):',
             'def make_message(rec, addr, msgid, sender=FROM_ADDR):',
             'LIVE message sender argument')
    s = once(s, "msg['From'] = FROM_ADDR", "msg['From'] = sender", 'LIVE From header')
    s = once(s,
             '    sent = failed = cancelled = 0\n    rows = db.execute(',
             "    sender = smtp.get('from') or settings_module.smtp_config(portal_db)['from']\n    sent = failed = cancelled = 0\n    rows = db.execute(",
             'LIVE sender lookup')
    s = once(s,
             """                message = make_message(payload, addr, message_id)
                submit_one(smtp['host'], smtp['port'], FROM_ADDR, addr, message, smtp_factory)""",
             """                message = make_message(payload, addr, message_id, sender=sender)
                submit_one(smtp['host'], smtp['port'], sender, addr, message, smtp_factory)""",
             'LIVE SMTP message and envelope sender')
    s = once(s,
             "if smtp['from'] != FROM_ADDR or smtp['auth'] or smtp['starttls']:",
             "if smtp['auth'] or smtp['starttls']:",
             'LIVE hardcoded sender guard')
    ast.parse(s)
    return s

PATCHERS = {'settings': patch_settings, 'admin': patch_admin, 'html': patch_html, 'live': patch_live}

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('--check', '--apply'):
        raise SystemExit('Usage: apply_editable_from_patch.py --check | --apply')
    for label, target in FILES.items():
        if not target.is_file():
            raise SystemExit(f'Missing {label}: {target}')
    try:
        results = {label: PATCHERS[label](target.read_text(encoding='utf-8'))
                   for label, target in FILES.items()}
    except Exception as exc:
        raise SystemExit(f'PATCH REFUSED (nothing changed): {exc}') from exc
    if sys.argv[1] == '--check':
        print('EDITABLE FROM PATCH CHECK: PASS (no files or database changed)')
        return
    backups = {label: target.with_name(target.name + '.before-editable-from')
               for label, target in FILES.items()}
    if any(target.exists() for target in backups.values()):
        raise SystemExit('PATCH REFUSED: one or more .before-editable-from backups already exist')
    for label, target in FILES.items():
        shutil.copy2(target, backups[label])
    try:
        for label, target in FILES.items():
            target.write_text(results[label], encoding='utf-8')
    except Exception:
        for label, target in FILES.items():
            shutil.copy2(backups[label], target)
        raise
    print('EDITABLE FROM PATCH APPLIED: 4 source files')
    print('SMTP sender column will be added during next Portal startup; existing values preserved')

if __name__ == '__main__':
    main()
