import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path

import mportal_mail_live as live
import alert_settings as cfg


class FakeSMTP:
    attempts = []
    fail = False
    def __init__(self, host, port, timeout):
        self.host, self.port = host, port
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def ehlo(self): return (250,b'OK')
    def send_message(self,msg,from_addr,to_addrs):
        self.attempts.append((self.host,self.port,from_addr,to_addrs[0],str(msg['Subject'])))
        if self.fail: raise OSError('Relay unreachable')
        return {}


def entry(eid, name, kind='service'):
    return {'id':str(eid),'name':name,'kind':kind,'severity':4}


class MailLiveTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.portal_db=self.root/'portal.db'
        self.state=self.root/'alerts.sqlite3'
        with closing(sqlite3.connect(self.portal_db)) as db, db:
            db.execute('CREATE TABLE mp_projects(id INTEGER PRIMARY KEY,name TEXT)')
            db.execute('CREATE TABLE mp_project_hosts(host_id TEXT PRIMARY KEY,project_id INTEGER)')
        cfg.ensure_schema(self.portal_db)
        cfg.set_general_recipients(self.portal_db, 'admin','general@example.com')
        cfg.add_or_update_rule(self.portal_db,'admin',scope='host',host_id='10917',
                               service_name='w32time',mode='critical',severity=4,allowed_hostids={'10917'})
        self.p = cfg.effective_for_host(self.portal_db,'10917')
        self.p['critical_map']={'w32time':4}
        self.hosts={'10917':{'name':'ML2SRV01','host':'ML2SRV01','maintenance_status':'0'}}
        self.smtp={'host':'relay.example.com','port':25}
        FakeSMTP.attempts=[]
        FakeSMTP.fail=False
        self.db=sqlite3.connect(self.state)
        self.addCleanup(self.db.close)
        live.ensure_state(self.db)
        self.db.commit()

    def staged(self, now, current=None, suppressed=None):
        current = current or {}
        # Override the policy's independent Zabbix open-problem reconciliation.
        old = live.policy.active_candidate_snapshot
        live.policy.active_candidate_snapshot=lambda *a: (current, set(suppressed or []))
        try:
            with self.db:
                return live.schedule(self.db,self.hosts,{'10917':self.p}, {}, {},now)
        finally:
            live.policy.active_candidate_snapshot=old

    def ship(self, now, active, suppressed=None):
        with redirect_stdout(io.StringIO()):
            return live.deliver(self.db,self.smtp,str(self.portal_db),cfg,self.hosts,
                                {'10917':self.p},active,set(suppressed or []),now,FakeSMTP)

    def queued(self):
        return self.db.execute("SELECT COUNT(*) FROM outbox WHERE status IN ('queued','retry')").fetchone()[0]

    def test_smtp_validation_and_fixed_sender(self):
        cfg.set_smtp_config(self.portal_db,'admin','relay2.example.com',2525)
        self.assertEqual(cfg.smtp_config(self.portal_db)['host'],'relay2.example.com')
        self.assertEqual(cfg.smtp_config(self.portal_db)['port'],2525)
        self.assertEqual(cfg.smtp_config(self.portal_db)['from'],'mportal@example.com')
        with self.assertRaises(ValueError): cfg.set_smtp_config(self.portal_db,'admin','http://bad',25)
        with self.assertRaises(ValueError): cfg.set_smtp_config(self.portal_db,'admin','relay',0)

    def test_two_minute_grouping_and_live(self):
        events=[entry(1,'w32time down'),entry(2,'second service down')]
        self.staged(100,{'10917':events})
        self.assertEqual(self.queued(),0)
        self.staged(221,{'10917':events})
        self.assertEqual(self.queued(),1)
        sent,failed,_=self.ship(222,{'10917':events})
        self.assertEqual((sent,failed),(1,0))
        self.assertEqual(len(FakeSMTP.attempts),1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbox WHERE status='accepted'").fetchone()[0],1)
        self.assertEqual(self.db.execute('SELECT last_sent_at FROM host_notifications').fetchone()[0],222)

    def test_failed_relay_retries_durably(self):
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events}); self.staged(221,{'10917':events})
        FakeSMTP.fail=True
        sent,fail,_=self.ship(222,{'10917':events})
        self.assertEqual((sent,fail),(0,1))
        self.staged(260,{'10917':events})
        self.assertEqual(self.queued(),1)
        self.assertEqual(self.db.execute("SELECT attempts FROM outbox WHERE status='retry'").fetchone()[0],1)
        FakeSMTP.fail=False
        self.assertEqual(self.ship(283,{'10917':events})[0],1)
        self.assertEqual(self.queued(),0)

    def test_cancel_if_problem_recovers_before_delivery(self):
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events}); self.staged(221,{'10917':events})
        self.staged(240,{})
        self.assertEqual(self.queued(),0)
        self.assertEqual(self.ship(241,{})[0],0)
        self.assertEqual(FakeSMTP.attempts,[])

    def test_maintenance_blocks_pending_and_restart_window(self):
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events}); self.staged(221,{'10917':events})
        self.staged(230,{},suppressed={'10917'})
        self.assertEqual(self.queued(),0)
        self.assertEqual(self.ship(231,{},suppressed={'10917'})[0],0)
        self.staged(300,{'10917':events}); self.staged(421,{'10917':events})
        self.assertEqual(self.ship(422,{'10917':events})[0],1)

    def test_recipient_change_blocks_stale_route(self):
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events}); self.staged(221,{'10917':events})
        cfg.set_general_recipients(self.portal_db,'admin','new@example.com')
        self.assertEqual(self.ship(222,{'10917':events})[2],1)
        self.assertEqual(FakeSMTP.attempts,[])
        self.p=cfg.effective_for_host(self.portal_db,'10917')
        self.p['critical_map']={'w32time':4}
        self.staged(230,{'10917':events}); self.staged(351,{'10917':events})
        self.assertEqual(self.ship(352,{'10917':events})[0],1)
        self.assertEqual(FakeSMTP.attempts[0][3],'new@example.com')

    def test_partial_recipients_not_resent_after_failure(self):
        # Simulate one accepted recipient and a later retry for the rest.
        cfg.set_general_recipients(self.portal_db,'admin','a@example.com,b@example.com')
        self.p=cfg.effective_for_host(self.portal_db,'10917')
        self.p['critical_map']={'w32time':4}
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events}); self.staged(221,{'10917':events})
        oid=self.db.execute("SELECT id FROM outbox WHERE status='queued'").fetchone()[0]
        self.db.execute("UPDATE outbox SET accepted_json='[\"a@example.com\"]' WHERE id=?",(oid,))
        self.db.commit()
        self.assertEqual(self.ship(222,{'10917':events})[0],1)
        self.assertEqual(len(FakeSMTP.attempts),1)
        self.assertEqual(FakeSMTP.attempts[0][3],'b@example.com')

    def test_malformed_project_route_never_falls_back(self):
        with self.db:
            self.db.execute('INSERT INTO host_notifications(hostid,last_json,policy_key) VALUES (?,?,?)',
                            ('10917','[]',live.key_for(self.p)))
        with closing(sqlite3.connect(self.portal_db)) as d,d:
            d.execute('INSERT INTO mp_projects VALUES(1,"Alfa")')
            d.execute('INSERT INTO mp_project_hosts VALUES("10917",1)')
        self.assertEqual(self.p['scope'],'general')
        self.p=cfg.effective_for_host(self.portal_db,'10917')
        self.p['critical_map']={'w32time':4}
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events})
        self.assertEqual(self.queued(),0)
        self.assertEqual(self.p['recipients'],[])

    def test_full_api_cycle_baseline_then_real_smtp(self):
        class FakeAPI:
            def __init__(self):
                self.events=[{'eventid':'1','objectid':'201','clock':'50',
                              'name':'old event','severity':'4','value':'1'}]
                self.problems=[]
            def call(self, method, params):
                if method == 'host.get':
                    return [{'hostid':'10917','name':'ML2SRV01','host':'ML2SRV01',
                             'status':'0','maintenance_status':'0',
                             'parentTemplates':[{'templateid':'10081'}]}]
                if method == 'trigger.get':
                    return [{'triggerid':'201','description':'w32time is not running',
                             'status':'0','priority':'4',
                             'items':[{'key_':'service.info[w32time,state]'}],
                             'hosts':[{'hostid':'10917'}]}]
                if method == 'problem.get': return self.problems
                if method == 'event.get':
                    ordered=[e for e in self.events if int(e['eventid'])>=int(params.get('eventid_from',0))]
                    ordered.sort(key=lambda e:int(e['eventid']),
                                 reverse=params['sortorder']=='DESC')
                    return [{k:v for k,v in e.items() if k in params['output']}
                            for e in ordered[:params['limit']]]
                raise AssertionError(method)
        api=FakeAPI()
        module_path=str(Path(__file__).resolve().parent)
        out=io.StringIO()
        with redirect_stdout(out):
            live.run(api,str(self.portal_db),self.state,'10081',module_path,100,
                     smtp_factory=FakeSMTP)
        self.assertIn('LIVE_BASELINE_CREATED',out.getvalue())
        self.assertEqual(FakeSMTP.attempts,[])
        api.events.append({'eventid':'2','objectid':'201','clock':'110',
                           'name':'w32time down','severity':'4','value':'1'})
        api.problems=[{'eventid':'2','objectid':'201','name':'w32time down',
                       'severity':'4','suppressed':'0','suppression_data':[]}]
        with redirect_stdout(io.StringIO()):
            live.run(api,str(self.portal_db),self.state,'10081',module_path,130,
                     smtp_factory=FakeSMTP)
        self.assertEqual(FakeSMTP.attempts,[])
        with redirect_stdout(io.StringIO()):
            live.run(api,str(self.portal_db),self.state,'10081',module_path,251,
                     smtp_factory=FakeSMTP)
        self.assertEqual(len(FakeSMTP.attempts),1)
        self.assertEqual(FakeSMTP.attempts[0][3],'general@example.com')

    def test_reminder_four_hours(self):
        events=[entry(1,'w32time down')]
        self.staged(100,{'10917':events}); self.staged(221,{'10917':events})
        self.ship(222,{'10917':events})
        self.staged(222+14399,{'10917':events})
        self.assertEqual(self.queued(),0)
        self.staged(222+14401,{'10917':events})
        self.assertEqual(self.queued(),1)
        self.assertEqual(self.ship(222+14402,{'10917':events})[0],1)
        self.assertEqual(len(FakeSMTP.attempts),2)

if __name__=='__main__': unittest.main()
