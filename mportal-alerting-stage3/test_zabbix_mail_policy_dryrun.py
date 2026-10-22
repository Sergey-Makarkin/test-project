#!/usr/bin/env python3
"""Stage 3 tests: real policy implementation, isolated temp DB, fake Zabbix. No SMTP."""
from contextlib import redirect_stdout, closing
import importlib.util
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import zabbix_mail_policy_dryrun as a

# Production test execution uses already-installed code in /opt; outside production
# these tests can be run with an explicit PORTAL_ALERT_SETTINGS_DIR.
import os
POLICY_SRC = Path(os.environ.get('PORTAL_ALERT_SETTINGS_DIR', '/opt/maintenance-portal-demo'))


def load_settings():
    return a.load_portal_settings(str(POLICY_SRC))


class FakeAPI:
    def __init__(self):
        self.events = []
        self.problems = []
        self.hosts = [
            {'hostid': '10917', 'name':'ML2SRV01', 'host':'ML2SRV01',
             'status':'0', 'maintenance_status':'0',
             'parentTemplates':[{'templateid':'10081'}]},
            {'hostid': '10918', 'name':'ML2SRV02', 'host':'ML2SRV02',
             'status':'0', 'maintenance_status':'0',
             'parentTemplates':[{'templateid':'10081'}]},
            {'hostid': '10919', 'name':'GENERAL01', 'host':'GENERAL01',
             'status':'0', 'maintenance_status':'0',
             'parentTemplates':[{'templateid':'10081'}]},
        ]
        self.triggers = [
            self.tr('201','10917','service.info[w32time,state]'),
            self.tr('202','10917','service.info[Spooler,state]'),
            self.tr('203','10918','service.info[Spooler,state]'),
            self.tr('204','10919','service.info[Spooler,state]'),
            self.tr('205','10917','zabbix[host,agent,available]'),
            self.tr('206','10917','service.info["GxCVD(Instance001)",state]'),
        ]
    @staticmethod
    def tr(tid,hid,key):
        return {'triggerid':tid,'status':'0','priority':'4',
                'items':[{'key_':key}], 'hosts':[{'hostid':hid}]}
    def call(self,method,params):
        if method == 'host.get':return self.hosts
        if method == 'trigger.get':return self.triggers
        if method == 'problem.get':return self.problems
        if method == 'event.get':
            events = [e for e in self.events if int(e['eventid'])>=int(params.get('eventid_from',0))]
            events.sort(key=lambda e:int(e['eventid']),reverse=params['sortorder']=='DESC')
            return [{k:v for k,v in e.items() if k in params['output']} for e in events[:params.get('limit',500)]]
        raise AssertionError(method)


def event(eid,trigger,sev=4,clock=110,value=1):
    return {'eventid':str(eid),'objectid':str(trigger),'clock':str(clock),
            'name':'trigger '+str(trigger), 'severity':str(sev),'value':str(value)}


def problem(eid,trigger,sev=4,suppressed=False):
    return {'eventid':str(eid),'objectid':str(trigger),'name':'trigger '+str(trigger),
            'severity':str(sev),'suppressed':str(int(suppressed)),
            'suppression_data':[{'maintenanceid':'5'}] if suppressed else []}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.db=self.root/'portal.sqlite3'
        self.state=self.root/'stage3.sqlite3'
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE mp_projects(id INTEGER PRIMARY KEY,name TEXT)')
            db.execute('CREATE TABLE mp_project_hosts(host_id TEXT PRIMARY KEY,project_id INTEGER)')
            db.execute('INSERT INTO mp_projects VALUES(1,"Alfa")')
            db.execute('INSERT INTO mp_projects VALUES(2,"Beta")')
            db.execute('INSERT INTO mp_project_hosts VALUES("10917",1)')
            db.execute('INSERT INTO mp_project_hosts VALUES("10918",2)')
        self.cfg=load_settings()
        self.cfg.ensure_schema(str(self.db))
        self.api=FakeAPI()

    def recipients(self, general='general@biokob.com', alfa='alfa@biokob.com', beta='beta@biokob.com'):
        self.cfg.set_general_recipients(self.db,'admin',general)
        self.cfg.set_project_recipients(self.db,'admin',1,alfa)
        self.cfg.set_project_recipients(self.db,'admin',2,beta)

    def rule(self,service,scope='project',project_id=1,host_id=None,mode='critical',severity=4):
        self.cfg.add_or_update_rule(str(self.db),'admin',scope=scope,
                                    project_id=project_id if scope=='project' else None,
                                    host_id=host_id if scope=='host' else None,
                                    service_name=service, mode=mode, severity=severity,
                                    allowed_hostids={'10917','10918','10919'})

    def run_at(self,now):
        output=io.StringIO()
        with redirect_stdout(output):
            a.run(self.api,str(self.db),self.state,'10081',now,code_dir=str(POLICY_SRC))
        return output.getvalue()

    def mail(self,output):
        return [json.loads(line[len('WOULD_EMAIL '):]) for line in output.splitlines()
                if line.startswith('WOULD_EMAIL ')]

    def test_baseline_then_project_recipients_and_grouping(self):
        self.recipients()
        self.rule('w32time')
        self.rule('Spooler')
        self.assertIn('BASELINE CREATED',self.run_at(100))
        self.api.events=[event(2,201,clock=110),event(3,202,clock=112)]
        self.api.problems=[problem(2,201),problem(3,202)]
        self.assertEqual(self.mail(self.run_at(130)),[])
        mails=self.mail(self.run_at(251))
        self.assertEqual(len(mails),1)
        self.assertEqual(mails[0]['to'],['alfa@biokob.com'])
        self.assertEqual(mails[0]['from'],'mportal@biokob.com')
        self.assertEqual(mails[0]['active_count'],2)
        self.assertEqual(mails[0]['route'],'PROJECT:1:Alfa')

    def test_unconfigured_project_no_general_fallback(self):
        self.recipients(alfa='')
        self.rule('w32time')
        self.run_at(100)
        self.api.events=[event(2,201)]
        self.api.problems=[problem(2,201)]
        self.run_at(120)
        out=self.run_at(241)
        self.assertIn('WOULD_BLOCK_NO_RECIPIENTS hostid=10917 scope=project',out)
        self.assertEqual(self.mail(out),[])
        self.cfg.set_project_recipients(self.db,'admin',1,'alfa@biokob.com')
        self.assertEqual(self.mail(self.run_at(242)),[])
        self.assertEqual(len(self.mail(self.run_at(363))),1)

    def test_global_critical_exclusion_host_and_severity(self):
        self.recipients()
        self.rule('Spooler',scope='global')
        self.rule('Spooler',scope='project',mode='exclude')
        self.rule('w32time',severity=5)  # Event High but rule demands Disaster.
        self.run_at(100)
        self.api.events=[event(2,201),event(3,202),event(4,204)]
        self.api.problems=[problem(2,201),problem(3,202),problem(4,204)]
        self.run_at(120)
        mails=self.mail(self.run_at(241))
        self.assertEqual(len(mails),1)
        self.assertEqual(mails[0]['route'],'GENERAL')
        self.assertEqual(mails[0]['to'],['general@biokob.com'])
        self.assertEqual(mails[0]['active_count'],1)

    def test_new_problem_update_and_partial_recovery(self):
        self.recipients()
        self.rule('w32time')
        self.rule('Spooler')
        self.run_at(100)
        self.api.events=[event(2,201)]
        self.api.problems=[problem(2,201)]
        self.run_at(130)
        self.mail(self.run_at(251))
        self.api.events.append(event(3,202,clock=260))
        self.api.problems.append(problem(3,202))
        self.run_at(300)
        update=self.mail(self.run_at(421))[0]
        self.assertIn('[UPDATE]',update['subject'])
        self.assertEqual(len(update['new']),1)
        self.api.events.append(event(4,202,clock=430,value=0))
        self.api.problems=[p for p in self.api.problems if p['eventid']!='3']
        self.run_at(450)
        recovery=self.mail(self.run_at(571))[0]
        self.assertEqual(recovery['recovered'],['trigger 202'])
        self.assertEqual(recovery['active_count'],1)

    def test_policy_change_not_false_recovery(self):
        self.recipients()
        self.rule('w32time')
        self.run_at(100)
        self.api.events=[event(2,201)]
        self.api.problems=[problem(2,201)]
        self.run_at(130)
        self.mail(self.run_at(251))
        self.rule('w32time',mode='exclude')
        self.run_at(300)
        m=self.mail(self.run_at(421))[0]
        self.assertEqual(m['recovered'],[])
        self.assertEqual(m['no_longer_monitored'],['trigger 201'])
        self.assertIn('[POLICY CHANGE]',m['subject'])

    def test_project_move_prevents_old_recipient(self):
        self.recipients()
        self.rule('Spooler',scope='global')
        self.run_at(100)
        self.api.events=[event(2,202)]
        self.api.problems=[problem(2,202)]
        self.run_at(130)
        self.assertEqual(self.mail(self.run_at(251))[0]['to'],['alfa@biokob.com'])
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE mp_project_hosts SET project_id=2 WHERE host_id="10917"')
        out=self.run_at(300)
        self.assertIn('ROUTE_CHANGED',out)
        self.assertEqual(self.mail(out),[])
        self.assertEqual(self.mail(self.run_at(421))[0]['to'],['beta@biokob.com'])

    def test_agent_event_without_service_rule(self):
        self.recipients()
        self.run_at(100)
        self.api.events=[event(2,205,sev=4)]
        self.api.problems=[problem(2,205,sev=4)]
        self.run_at(130)
        mail=self.mail(self.run_at(251))[0]
        self.assertEqual(mail['active_count'],1)
        self.assertIn('alfa@biokob.com',mail['to'])

    def test_critical_name_from_quoted_item_key(self):
        self.assertEqual(a.service_name_from_item_key('service.info["GxCVD(Instance001)",state]'),
                         'GxCVD(Instance001)')
        self.assertEqual(a.service_name_from_item_key('service.info["Zabbix Agent 2",state]'),
                         'Zabbix Agent 2')
        self.assertEqual(a.service_name_from_item_key('agent.ping'),None)

    def test_invalid_project_reference_fails_closed(self):
        self.recipients()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE mp_project_hosts SET project_id=999 WHERE host_id="10917"')
        with self.assertRaisesRegex(RuntimeError,'Invalid project reference'):
            self.run_at(100)

    def test_baseline_old_high_remains_quiet(self):
        self.recipients()
        self.rule('w32time')
        self.api.events=[event(1,201,clock=90)]
        self.api.problems=[problem(1,201)]
        self.assertIn('BASELINE CREATED',self.run_at(100))
        self.assertEqual(self.mail(self.run_at(15000)),[])

if __name__=='__main__': unittest.main()
