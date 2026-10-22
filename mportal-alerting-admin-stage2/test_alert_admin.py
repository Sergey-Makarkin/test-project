from contextlib import closing
"""Offline FastAPI route permission tests; no production DB or LDAP calls."""
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

# On deployment the real project_access.py exists and ldap3 is installed.
# In a bare offline test environment we stub only feature-flag helper.
try:
    import project_access
except ImportError:
    project_access = types.ModuleType('project_access')
    project_access.enabled = lambda: True
    sys.modules['project_access'] = project_access

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates
import alert_settings
import alert_admin


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.db = str(base/'portal.sqlite3')
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE mp_projects(id INTEGER PRIMARY KEY,name TEXT)')
            db.execute('CREATE TABLE mp_project_hosts(host_id TEXT PRIMARY KEY,project_id INTEGER)')
            db.execute("INSERT INTO mp_projects VALUES(1,'Alfa')")
            db.execute("INSERT INTO mp_project_hosts VALUES('10917',1)")
        alert_settings.ensure_schema(self.db)
        templates_dir = base/'templates'
        templates_dir.mkdir()
        (templates_dir/'alerting.html').write_text('Admin alert settings: {{ general_recipients_text }} {{ csrf }}', encoding='utf-8')
        app = FastAPI()
        self.role = 'admin'

        def identity(request):
            return {'role':self.role, 'scope':self.role, 'csrf':'secure-token', 'name':'tester@example.com'}

        def check_csrf(request, token):
            if token != 'secure-token':
                raise HTTPException(403, 'CSRF')

        alert_admin.install_alert_admin_routes(
            app, self.db, Jinja2Templates(directory=str(templates_dir)), identity,
            check_csrf, lambda:{'10917':{'hostid':'10917','name':'srv1'},
                                  '10919':{'hostid':'10919','name':'srv2'}})
        self.client = TestClient(app, follow_redirects=False)
        self.flag = patch.object(project_access, 'enabled', return_value=True)
        self.flag.start()

    def tearDown(self):
        self.flag.stop()
        self.client.close()
        self.tmp.cleanup()

    def test_admin_get_and_save(self):
        self.assertEqual(self.client.get('/admin/alerting').status_code, 200)
        res = self.client.post('/admin/alerting/recipients/general', data={
            'csrf_token':'secure-token', 'recipients':'noc@example.com'})
        self.assertEqual(res.status_code, 303)
        self.assertEqual(alert_settings.effective_for_host(self.db,'10919')['recipients'],
                         ['noc@example.com'])

    def test_operator_denied_get_and_post(self):
        self.role = 'operator'
        self.assertEqual(self.client.get('/admin/alerting').status_code,403)
        self.assertEqual(self.client.post('/admin/alerting/recipients/general',data={
            'csrf_token':'secure-token', 'recipients':'evil@example.com'}).status_code,403)
        self.assertEqual(alert_settings.effective_for_host(self.db,'10919')['recipients'],[])

    def test_csrf_denied(self):
        res=self.client.post('/admin/alerting/recipients/general',data={
            'csrf_token':'invalid', 'recipients':'noc@example.com'})
        self.assertEqual(res.status_code,403)

    def test_project_mail_routing(self):
        res=self.client.post('/admin/alerting/recipients/project/1',data={
            'csrf_token':'secure-token','recipients':'alfa@example.com'})
        self.assertEqual(res.status_code,303)
        self.assertEqual(alert_settings.effective_for_host(self.db,'10917')['recipients'],
                         ['alfa@example.com'])
        self.assertEqual(alert_settings.effective_for_host(self.db,'10919')['recipients'],[])

    def test_invalid_host_rule_rejected(self):
        res=self.client.post('/admin/alerting/rules',data={
            'csrf_token':'secure-token','scope':'host','host_id':'99999',
            'service_name':'MSSQLSERVER','mode':'critical','severity':'4'})
        self.assertEqual(res.status_code,422)

    def test_valid_host_rule_and_preview(self):
        res=self.client.post('/admin/alerting/rules',data={
            'csrf_token':'secure-token','scope':'host','host_id':'10917',
            'service_name':'GxCVD(Instance001)','mode':'critical','severity':'4'})
        self.assertEqual(res.status_code,303)
        self.assertEqual(self.client.get('/admin/alerting?host_id=10917').status_code,200)
        self.assertEqual(len(alert_settings.effective_for_host(self.db,'10917')['critical_services']),1)


if __name__ == '__main__':
    unittest.main()
