from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

import alert_settings as a


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name)/'test.sqlite3')
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE mp_projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL)')
            db.execute('CREATE TABLE mp_project_hosts(host_id TEXT PRIMARY KEY, project_id INTEGER NOT NULL)')
            db.executemany('INSERT INTO mp_projects VALUES(?,?)', [(1, 'Alfa'), (2, 'Beta')])
            db.executemany('INSERT INTO mp_project_hosts VALUES(?,?)', [('10917', 1), ('10918', 2)])
        a.ensure_schema(self.db)
        self.hosts = {'10917', '10918', '10919'}

    def tearDown(self):
        self.temp.cleanup()

    def rule(self, scope, service, mode='critical', severity=4, project_id=None, host_id=None):
        return a.add_or_update_rule(self.db, 'admin@example.com', scope=scope,
               project_id=project_id, host_id=host_id, service_name=service,
               mode=mode, severity=severity, allowed_hostids=self.hosts)

    def test_idempotent_schema_and_project_data(self):
        a.ensure_schema(self.db)
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM mp_projects').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM mp_alert_general').fetchone()[0], 1)

    def test_default_no_route_and_no_service(self):
        for hid in self.hosts:
            v = a.effective_for_host(self.db, hid)
            self.assertFalse(v['route_configured'])
            self.assertEqual(v['critical_services'], [])
            self.assertEqual(a.build_lld_regex(v['critical_services']), '^$')

    def test_general_never_fallback_for_project(self):
        a.set_general_recipients(self.db, 'admin', 'general@example.com')
        self.assertEqual(a.effective_for_host(self.db, '10919')['recipients'], ['general@example.com'])
        self.assertEqual(a.effective_for_host(self.db, '10917')['recipients'], [])

    def test_project_isolation(self):
        a.set_project_recipients(self.db, 'admin', 1, 'alfa@example.com')
        a.set_project_recipients(self.db, 'admin', 2, 'beta@example.com')
        self.assertEqual(a.effective_for_host(self.db, '10917')['recipients'], ['alfa@example.com'])
        self.assertEqual(a.effective_for_host(self.db, '10918')['recipients'], ['beta@example.com'])
        self.assertEqual(a.effective_for_host(self.db, '10919')['recipients'], [])

    def test_precedence_global_project_host(self):
        self.rule('global', 'MSSQLSERVER')
        self.rule('global', 'WinRM')
        self.rule('project', 'MSSQLSERVER', 'exclude', project_id=1)
        self.rule('host', 'MSSQLSERVER', 'critical', severity=5, host_id='10917')
        self.rule('host', 'WinRM', 'exclude', host_id='10917')
        critical = a.effective_for_host(self.db, '10917')['critical_services']
        self.assertEqual(critical, [{'name':'MSSQLSERVER','severity':5}])
        self.assertEqual(len(a.effective_for_host(self.db, '10918')['critical_services']), 2)

    def test_case_insensitive_upsert(self):
        r1 = self.rule('global', 'w32time')
        r2 = self.rule('global', 'W32Time', severity=5)
        self.assertEqual(r1, r2)
        self.assertEqual(a.effective_for_host(self.db, '10919')['critical_services'],
                         [{'name':'w32time','severity':5}])

    def test_reject_invalid_email(self):
        for value in ['a@example.com\r\nBcc:evil@example.org', 'noat', 'Name <a@example.com>',
                      'bad@example..com']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                a.normalize_recipients(value)
        self.assertEqual(a.normalize_recipients('A@example.com, a@example.com'), ['a@example.com'])

    def test_reject_unlisted_host_and_unknown_project(self):
        with self.assertRaises(ValueError):
            self.rule('host', 'Spooler', host_id='10920')
        with self.assertRaises(ValueError):
            self.rule('project', 'Spooler', project_id=99)

    def test_regex_escaped_short_names(self):
        regex = a.build_lld_regex([{'name':'GxCVD(Instance001)', 'severity':4},
                                   {'name':'Zabbix Agent 2', 'severity':4}])
        self.assertIn(r'GxCVD\(Instance001\)', regex)
        self.assertTrue(regex.startswith('(?i)^'))

    def test_audit_and_delete(self):
        ident = self.rule('host', 'W32Time', host_id='10917')
        a.remove_rule(self.db, 'admin', ident)
        self.assertEqual(a.effective_for_host(self.db, '10917')['critical_services'], [])
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM mp_alert_audit').fetchone()[0], 2)

    def test_read_only_snapshot(self):
        a.set_general_recipients(self.db, 'admin', 'a@example.com')
        data = a.snapshot(self.db)
        self.assertEqual(len(data['projects']), 2)
        self.assertEqual(data['general_recipients'], ['a@example.com'])

    def test_project_delete_cascade(self):
        a.set_project_recipients(self.db, 'admin', 1, 'a@example.com')
        self.rule('project', 'W32Time', project_id=1)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('DELETE FROM mp_project_hosts WHERE project_id=1')
            db.execute('DELETE FROM mp_projects WHERE id=1')
        self.assertEqual([p['id'] for p in a.snapshot(self.db)['projects']], [2])
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM mp_alert_service_rules').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
