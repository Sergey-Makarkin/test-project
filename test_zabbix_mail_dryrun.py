import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import zabbix_mail_dryrun as a


class FakeAPI:
    def __init__(self):
        self.calls=[]
        self.events=[]
        self.problems=[]
        self.hosts=[{'hostid':'10917','name':'ML2SRV01','host':'ML2SRV01', 'status':'0',
                     'maintenance_status':'0', 'parentTemplates':[{'templateid':'10081'}]},
                    {'hostid':'10918','name':'ML2SRV02','host':'ML2SRV02','status':'0',
                     'maintenance_status':'0','parentTemplates':[{'templateid':'10081'}]}]
        self.triggers=[{'triggerid':'201','priority':'4','status':'0','items':[{'key_':'service.info[w32time,state]'}],
                        'hosts':[{'hostid':'10917'}]},
                       {'triggerid':'202','priority':'4','status':'0','items':[{'key_':'service.info[w32time,state]'}],
                        'hosts':[{'hostid':'10918'}]}]
    def call(self, method, params):
        self.calls.append((method,params))
        if method=='host.get': return self.hosts
        if method=='trigger.get': return self.triggers
        if method=='problem.get': return self.problems
        if method=='event.get':
            result=[e for e in self.events if int(e['eventid'])>=int(params.get('eventid_from', 0))]
            result.sort(key=lambda x:int(x['eventid']), reverse=params['sortorder']=='DESC')
            return [{k:v for k,v in e.items() if k in params['output']} for e in result[:params.get('limit',500)]]
        raise AssertionError(method)


def event(eid,trigger,sev,clock,name='w32time is not running',value='1'):
    return {'eventid':str(eid),'objectid':str(trigger),'severity':str(sev),'clock':str(clock),
            'name':name,'value':str(value)}


def problem(eid, trigger, severity=4, suppressed=False):
    return {'eventid':str(eid),'objectid':str(trigger),'severity':str(severity),
            'name':'w32time is not running', 'suppressed':str(int(suppressed)),
            'suppression_data':([{'maintenanceid':'123'}] if suppressed else [])}

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.dir=Path(self.tmp.name)
        self.portal=self.dir/'portal.db'
        with contextlib.closing(sqlite3.connect(self.portal)) as db, db:
            db.execute('CREATE TABLE mp_projects (id INTEGER PRIMARY KEY, name TEXT)')
            db.execute('CREATE TABLE mp_project_hosts (host_id TEXT PRIMARY KEY, project_id INTEGER)')
            db.execute('INSERT INTO mp_projects VALUES (1, "Alfa")')
            db.execute('INSERT INTO mp_project_hosts VALUES ("10917",1)')
        self.state=self.dir/'alerts.db'
        self.api=FakeAPI()
    def tearDown(self): self.tmp.cleanup()
    def runit(self,t):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            a.run(self.api,str(self.portal),self.state,'10081',t)
        return out.getvalue()
    def test_baseline_and_two_minute_group(self):
        self.api.events=[event(1,201,4,100)]
        self.api.problems=[problem(1,201)]
        self.assertIn('BASELINE CREATED',self.runit(100))
        self.assertNotIn('WOULD_EMAIL',self.runit(160))
        self.api.events.extend([event(2,201,4,170),event(3,202,4,171)])
        self.api.problems.extend([problem(2,201),problem(3,202)])
        self.assertNotIn('WOULD_EMAIL',self.runit(180))
        output=self.runit(301)
        self.assertEqual(output.count('WOULD_EMAIL'),2)
        self.assertIn('PROJECT:1:Alfa',output)
        self.assertIn('"route": "GENERAL"',output)
        self.assertNotIn('"id": "1"',output)
    def test_recovered_before_first_send(self):
        self.runit(100)
        self.api.events=[event(2,201,4,110)]
        self.api.problems=[problem(2,201)]
        self.runit(120)
        self.api.events.append(event(3,201,4,200,value=0))
        self.api.problems=[]
        self.assertNotIn('WOULD_EMAIL',self.runit(300))
    def test_recovery_and_reminder(self):
        self.runit(100)
        self.api.events=[event(2,201,4,110)]
        self.api.problems=[problem(2,201)]
        self.runit(130)
        self.assertIn('[PROBLEM]',self.runit(251))
        self.assertNotIn('WOULD_EMAIL',self.runit(252))
        self.assertIn('[REMINDER]',self.runit(251+14401))
        self.api.problems=[]
        self.assertNotIn('WOULD_EMAIL',self.runit(15000))
        self.assertIn('[RECOVERED]',self.runit(15121))
    def test_suppression_until_ends(self):
        self.runit(100)
        self.api.events=[event(2,201,4,110)]
        self.api.problems=[problem(2,201,suppressed=True)]
        self.runit(130)
        self.assertNotIn('WOULD_EMAIL',self.runit(350))
        self.api.problems=[problem(2,201,suppressed=False)]
        self.assertNotIn('WOULD_EMAIL',self.runit(360))
        self.assertIn('WOULD_EMAIL',self.runit(481))
    def test_reject_missing_project(self):
        with contextlib.closing(sqlite3.connect(self.portal)) as db, db:
            db.execute('UPDATE mp_project_hosts SET project_id=999')
        with self.assertRaisesRegex(RuntimeError,'Invalid project'):
            self.runit(100)
    def test_only_high_classified(self):
        self.runit(100)
        self.api.events=[event(2,201,3,110),event(3,999,5,110)]
        self.api.problems=[problem(2,201,severity=3)]
        self.runit(130)
        self.assertNotIn('WOULD_EMAIL',self.runit(260))
    def test_all_event_pages(self):
        self.runit(100)
        self.api.events=[event(i,201,4,100+i) for i in range(1,1103)]
        self.api.problems=[problem(1102,201)]
        self.runit(120)
        with contextlib.closing(sqlite3.connect(self.state)) as db:
            self.assertEqual(a.setting(db,'cursor'),'1102')
            n=db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]
            self.assertEqual(n,1102)

if __name__=='__main__': unittest.main()
