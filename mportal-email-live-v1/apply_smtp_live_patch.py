#!/usr/bin/env python3
"""Guarded patch: add SMTP host/port administration to deployed Stage 2 portal.
--check never writes. --apply touches only three existing files with backups.
"""
import ast
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
FILES = {
    'settings': ROOT / 'alert_settings.py',
    'admin': ROOT / 'alert_admin.py',
    'html': ROOT / 'templates' / 'alerting.html',
}

def once(data, old, new, what):
    count = data.count(old)
    if count != 1:
        raise ValueError(f'{what}: expected one anchor, found {count}')
    return data.replace(old, new, 1)


def patch_settings(s):
    s = once(s, "MAX_RULES = 5000\n", """MAX_RULES = 5000
SMTP_FROM = 'mportal@example.com'  # Fixed: not editable from Admin UI
SMTP_DEFAULT_HOST = 'ml2smtp01.example.com'
SMTP_DEFAULT_PORT = 25
SMTP_HOST_RE = re.compile(r'(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)\\Z')


def validate_smtp(host, port):
    host = str(host).strip().lower().rstrip('.')
    if not 1 <= len(host) <= 253 or not SMTP_HOST_RE.fullmatch(host) or '..' in host:
        raise ValueError('SMTP host must be a DNS name or IP address, without scheme/path')
    try:
        port = int(port)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid SMTP port') from exc
    if not 1 <= port <= 65535:
        raise ValueError('SMTP port must be 1..65535')
    return host, port


def smtp_config(path):
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
""", 'SMTP constants')
    s = once(s, "        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_general (", """        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_smtp (
            id INTEGER PRIMARY KEY CHECK(id=1),
            smtp_host TEXT NOT NULL,
            smtp_port INTEGER NOT NULL CHECK(smtp_port BETWEEN 1 AND 65535),
            updated_utc TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )''')
        db.execute('''INSERT OR IGNORE INTO mp_alert_smtp
            (id,smtp_host,smtp_port,updated_utc,updated_by)
            VALUES(1,?,?,?,'system')''',
            (SMTP_DEFAULT_HOST, SMTP_DEFAULT_PORT, utc_now()))
        db.execute('''CREATE TABLE IF NOT EXISTS mp_alert_general (""", 'SMTP table')
    s = once(s, "return {'general_recipients': general, 'general_recipients_text': ', '.join(general),", """smtp = smtp_config(path)
    return {'smtp_host': smtp['host'], 'smtp_port': smtp['port'], 'smtp_from': smtp['from'],
            'general_recipients': general, 'general_recipients_text': ', '.join(general),""", 'snapshot return')
    ast.parse(s)
    return s


def patch_admin(s):
    s = once(s, "    @router.post('/recipients/general')", """    @router.post('/smtp')
    def update_smtp(request: Request, smtp_host: str = Form(...), smtp_port: int = Form(...),
                    csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.set_smtp_config, db_path, user['name'], smtp_host, smtp_port)
        return go()

    @router.post('/recipients/general')""", 'SMTP route')
    ast.parse(s)
    return s


def patch_html(s):
    s = once(s, "<strong>CONFIGURATION ONLY / DRY RUN.</strong> SMTP is not connected. Saving rules does not change Zabbix triggers or LLD macros, and does not send email. Only Admin can change these settings.", "<strong>LIVE EMAIL CAPABLE.</strong> The alerting worker sends real email when its systemd timer is enabled. Saving these settings never sends a test email and never changes Zabbix triggers or LLD macros. Only Admin can change these settings.", 'UI status')
    s = once(s, '  <div class="alert-grid">', '''  <section class="card">
    <h2>SMTP Relay · LIVE delivery</h2>
    <p class="alert-muted">No SMTP AUTH and no STARTTLS. Use a trusted internal relay; delivery and transport security depend on that server. Sender is fixed.</p>
    <form class="alert-form" method="post" action="/admin/alerting/smtp">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">
      <label>SMTP server
        <input type="text" name="smtp_host" maxlength="253" required value="{{ smtp_host }}" placeholder="ml2smtp01.example.com">
      </label>
      <label>SMTP port
        <input type="number" name="smtp_port" min="1" max="65535" required value="{{ smtp_port }}">
      </label>
      <label>From (fixed)
        <input type="text" value="{{ smtp_from }}" disabled>
      </label>
      <button type="submit">Save SMTP settings</button>
    </form>
    <p class="alert-muted">SMTP configuration is read on every worker cycle. The sender cannot be changed here. The worker never uses AUTH/STARTTLS.</p>
  </section>
  <div class="alert-grid">''', 'SMTP form')
    from jinja2 import Environment
    Environment().parse(s)
    return s


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('--check','--apply'):
        raise SystemExit('Usage: apply_smtp_live_patch.py --check | --apply')
    for n,p in FILES.items():
        if not p.exists():
            raise SystemExit(f'Missing {n}: {p}')
    sources = {k: p.read_text(encoding='utf8') for k,p in FILES.items()}
    try:
        output = {'settings': patch_settings(sources['settings']),
                  'admin': patch_admin(sources['admin']),
                  'html': patch_html(sources['html'])}
    except Exception as exc:
        raise SystemExit(f'PATCH REFUSED (no changes): {exc}') from exc
    if sys.argv[1] == '--check':
        print('SMTP LIVE PATCH CHECK: PASS (no files or database changed)')
        return
    backups = {k: p.with_name(p.name + '.before-smtp-live') for k,p in FILES.items()}
    if any(p.exists() for p in backups.values()):
        raise SystemExit('PATCH REFUSED: existing .before-smtp-live backups found')
    for k,p in FILES.items():
        shutil.copy2(p,backups[k])
    try:
        for k,p in FILES.items():
            p.write_text(output[k],encoding='utf8')
    except Exception:
        for k,p in FILES.items():
            shutil.copy2(backups[k],p)
        raise
    print('SMTP LIVE PATCH APPLIED: alert_settings.py, alert_admin.py, templates/alerting.html')
    print('SMTP table will be created at next Maintenance Portal startup')

if __name__ == '__main__':
    main()
