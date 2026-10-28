"""Regression tests for configurable SMTP envelope/header sender, with fake SMTP."""
from contextlib import closing
import json
from email.message import EmailMessage
from pathlib import Path
import sqlite3
import tempfile
import unittest

import alert_settings as settings
import mportal_mail_live as live


class FakeSMTP:
    attempts = []
    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def ehlo(self):
        return 250, b'OK'
    def send_message(self, message, from_addr, to_addrs):
        self.attempts.append({'host': self.host, 'port': self.port,
                              'envelope_from': from_addr, 'header_from': message['From'],
                              'to': to_addrs[0]})
        return {}


class SMTPFromTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'portal.sqlite3'
        # Simulate database created by the previous live version: no smtp_from column.
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE mp_projects (id INTEGER PRIMARY KEY, name TEXT)')
            db.execute('CREATE TABLE mp_project_hosts (host_id TEXT PRIMARY KEY, project_id INTEGER)')
            db.execute('''CREATE TABLE mp_alert_smtp (
                 id INTEGER PRIMARY KEY, smtp_host TEXT NOT NULL, smtp_port INTEGER NOT NULL,
                 updated_utc TEXT NOT NULL, updated_by TEXT NOT NULL)''')
            db.execute('INSERT INTO mp_alert_smtp VALUES(1,?,?,?,?)',
                       ('mail-gateway.example.com', 2525, '2026-10-01T00:00:00+00:00', 'admin'))
        FakeSMTP.attempts.clear()

    def ready(self):
        settings.ensure_schema(self.path)
        return settings.smtp_config(self.path)

    def test_migrates_existing_settings_without_overwriting_server(self):
        smtp = self.ready()
        self.assertEqual(smtp['host'], 'mail-gateway.example.com')
        self.assertEqual(smtp['port'], 2525)
        self.assertEqual(smtp['from'], 'mportal@example.com')
        self.assertEqual(smtp['auth'], False)
        self.assertEqual(smtp['starttls'], False)
        settings.ensure_schema(self.path)  # Idempotent.
        with closing(sqlite3.connect(self.path)) as db:
            cols = [r[1] for r in db.execute('PRAGMA table_info(mp_alert_smtp)')]
        self.assertEqual(cols.count('smtp_from'), 1)

    def test_change_sender_and_snapshot(self):
        self.ready()
        settings.set_smtp_config(self.path, 'admin', 'relay2.example.com', 25,
                                 'operations+alert@example.com')
        smtp = settings.smtp_config(self.path)
        self.assertEqual(smtp['from'], 'operations+alert@example.com')
        self.assertEqual(settings.snapshot(self.path)['smtp_from'], smtp['from'])
        with closing(sqlite3.connect(self.path)) as db:
            op, raw = db.execute('SELECT operation,details FROM mp_alert_audit ORDER BY id DESC LIMIT 1').fetchone()
        self.assertEqual(op, 'smtp.update')
        self.assertEqual(json.loads(raw)['from'], 'operations+alert@example.com')

    def test_legacy_update_preserves_sender(self):
        self.ready()
        settings.set_smtp_config(self.path,'admin','relay.example.com',25,'noc@example.com')
        settings.set_smtp_config(self.path,'admin','relay-next.example.com',2526)
        self.assertEqual(settings.smtp_config(self.path)['from'], 'noc@example.com')

    def test_invalid_from_never_saved(self):
        self.ready()
        for sender in ['sender', 'Some Name <a@example.com>', 'a@example.com\r\nBcc:bad@example.com',
                       'a..b@example.com', '', 'a@example.com,other@example.com']:
            with self.subTest(sender=sender):
                with self.assertRaises(ValueError):
                    settings.set_smtp_config(self.path,'admin','relay.example.com',25,sender)
        self.assertEqual(settings.smtp_config(self.path)['from'],'mportal@example.com')
        self.assertEqual(settings.smtp_config(self.path)['host'],'mail-gateway.example.com')

    def test_live_uses_same_sender_in_header_and_smtp_envelope(self):
        self.ready()
        settings.set_smtp_config(self.path,'admin','relay2.example.com',25,'alerts@example.org')
        settings.set_general_recipients(self.path,'admin','test@example.net')
        settings.add_or_update_rule(self.path,'admin',scope='host',host_id='10917',
                                    service_name='w32time',mode='critical',severity=4,
                                    allowed_hostids={'10917'})
        p = settings.effective_for_host(self.path, '10917')
        p['critical_map'] = {'w32time': 4}
        hosts = {'10917': {'name':'ML2SRV01','host':'ML2SRV01','maintenance_status':'0'}}
        events = [{'id':'22','name':'w32time is not running','severity':4,'kind':'service'}]
        payload = live.record('10917',hosts['10917'],p,[],events,'CHANGED',120,{'22'})
        with closing(sqlite3.connect(Path(self.tmp.name)/'state.sqlite3')) as db:
            live.ensure_state(db)
            live.queue_mail(db, '10917', live.key_for(p), p['recipients'], payload, 220)
            db.commit()
            smtp = settings.smtp_config(self.path)
            sent, failed, cancelled = live.deliver(db,smtp,str(self.path),settings,
                hosts,{'10917':p},{'10917':events},set(),220,FakeSMTP)
        self.assertEqual((sent,failed,cancelled),(1,0,0))
        self.assertEqual(FakeSMTP.attempts[0]['header_from'],'alerts@example.org')
        self.assertEqual(FakeSMTP.attempts[0]['envelope_from'],'alerts@example.org')
        self.assertEqual(FakeSMTP.attempts[0]['host'],'relay2.example.com')

    def test_live_reads_changed_sender_each_cycle(self):
        self.ready()
        settings.set_smtp_config(self.path,'admin','relay.example.com',25,'before@example.com')
        self.assertEqual(settings.smtp_config(self.path)['from'], 'before@example.com')
        settings.set_smtp_config(self.path,'admin','relay.example.com',25,'after@example.com')
        self.assertEqual(settings.smtp_config(self.path)['from'], 'after@example.com')
        self.assertIn('after@example.com',live.make_message(
            {'status':'PROBLEM','host':'S','hostid':'1','project':'GENERAL',
             'current':[],'new':[],'recovered':[],'excluded':[]},
            'test@example.net','<test@example.com>',sender='after@example.com')['From'])

if __name__ == '__main__':
    unittest.main()
