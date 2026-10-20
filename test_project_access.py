import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

# If ldap3 isn't installed in the lightweight build container, stub only
# the imports needed for *offline* scope and database tests.
try:
    import ldap3
except ImportError:
    ldap3 = types.ModuleType('ldap3')
    for name in ('Server', 'Connection', 'Tls'):
        setattr(ldap3, name, lambda *a, **k: None)
    ldap3.SIMPLE = 'SIMPLE'
    ldap3.SUBTREE = 'SUBTREE'
    sys.modules['ldap3'] = ldap3
    utils = types.ModuleType('ldap3.utils')
    conv = types.ModuleType('ldap3.utils.conv')
    conv.escape_filter_chars = lambda val: val
    sys.modules['ldap3.utils'] = utils
    sys.modules['ldap3.utils.conv'] = conv
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import project_access as a
from fastapi import HTTPException

SID_ADMIN = 'S-1-5-21-111-500'
SID_GEN = 'S-1-5-21-111-501'
SID_A = 'S-1-5-21-111-502'
SID_B = 'S-1-5-21-111-503'
HOSTS = {str(i): {'hostid':str(i), 'name':f'win{i}'} for i in range(1,6)}

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'portal.sqlite3')
        a.ensure_schema(self.db)
        self.p1 = a.create_project(self.db, 'admin@example.com', 'Project Alpha')
        self.p2 = a.create_project(self.db, 'admin@example.com', 'Project Beta')
        a.add_group(self.db, 'admin@example.com', self.p1, {'sid': SID_A,
            'sam':'GG_PrjAlphaMaint', 'cn':'Project Alpha Maintenance', 'dn':'CN=A'})
        a.add_group(self.db, 'admin@example.com', self.p2, {'sid': SID_B,
            'sam':'GG_PrjBetaMaint', 'cn':'Project Beta Maintenance', 'dn':'CN=B'})
        a.assign_host(self.db, 'admin@example.com', self.p1, '2')
        a.assign_host(self.db, 'admin@example.com', self.p1, '3')
        a.assign_host(self.db, 'admin@example.com', self.p2, '4')
        self.env = patch.dict(os.environ, {'PORTAL_PROJECT_RBAC':'1'})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def rights(self, groups):
        return a._scope_from_groups(self.db, 'user@example.com', groups)

    def hosts(self, groups):
        return set(a.filter_hosts(self.db, self.rights(groups), HOSTS))

    def test_admin_sees_everything(self):
        self.assertEqual(self.hosts([(SID_ADMIN, 'gg_zabbix_maintenance_admins')]), set(HOSTS))

    def test_general_operator_is_excluded_from_projects(self):
        self.assertEqual(self.hosts([(SID_GEN, 'gg_zabbix_maintenance_operators')]), {'1','5'})

    def test_general_viewer_same_visibility_but_cannot_write(self):
        user = self.rights([('S-1-5-21-111-600', 'gg_zabbix_maintenance_viewers')])
        self.assertEqual(user['role'], 'viewer')
        self.assertEqual(set(a.filter_hosts(self.db, user, HOSTS)), {'1', '5'})

    def test_project_only_operator_login(self):
        user = self.rights([(SID_A, 'gg_prjalphamaint')])
        self.assertEqual((user['role'], user['scope']), ('operator', 'project'))
        self.assertEqual(set(a.filter_hosts(self.db, user, HOSTS)), {'2', '3'})

    def test_project_membership_beats_general_operator(self):
        self.assertEqual(self.hosts([(SID_A, 'gg_prjalphamaint'),
                           (SID_GEN, 'gg_zabbix_maintenance_operators')]), {'2','3'})

    def test_two_project_groups_form_union(self):
        self.assertEqual(self.hosts([(SID_A, 'gg_prjalphamaint'),
                           (SID_B, 'gg_prjbetamaint')]), {'2','3','4'})

    def test_admin_role_overrides_project_membership(self):
        self.assertEqual(self.hosts([(SID_ADMIN, 'gg_zabbix_maintenance_admins'),
                           (SID_A, 'gg_prjalphamaint')]), set(HOSTS))

    def test_unknown_group_is_denied(self):
        with self.assertRaises(HTTPException) as cm:
            self.rights([('S-1-5-21-111-600', 'not-a-portal-group')])
        self.assertEqual(cm.exception.status_code, 403)

    def test_unassigned_new_host_appears_only_general(self):
        new = {**HOSTS, '6': {'hostid':'6','name':'new-auto-discovered-host'}}
        user = self.rights([(SID_GEN, 'gg_zabbix_maintenance_operators')])
        self.assertIn('6', a.filter_hosts(self.db, user, new))
        project = self.rights([(SID_A, 'gg_prjalphamaint')])
        self.assertNotIn('6', a.filter_hosts(self.db, project, new))

    def test_cannot_assign_host_to_two_projects(self):
        with self.assertRaises(HTTPException) as cm:
            a.assign_host(self.db, 'admin', self.p2, '2')
        self.assertEqual(cm.exception.status_code, 409)

    def test_transfer_atomic_and_no_general_exposure(self):
        a.move_host(self.db, 'admin', '2', self.p2)
        self.assertEqual(self.hosts([(SID_A, 'gg_prjalphamaint')]), {'3'})
        self.assertEqual(self.hosts([(SID_B, 'gg_prjbetamaint')]), {'2','4'})
        self.assertEqual(self.hosts([(SID_GEN, 'gg_zabbix_maintenance_operators')]), {'1','5'})

    def test_release_goes_back_to_general(self):
        a.release_host(self.db, 'admin', self.p1, '3')
        self.assertIn('3', self.hosts([(SID_GEN, 'gg_zabbix_maintenance_operators')]))

    def test_delete_group_blocked_if_last_for_nonempty_project(self):
        snapshot = a.admin_snapshot(self.db, HOSTS)
        group_id = next(x for x in snapshot['projects'] if x['id'] == self.p1)['groups'][0]['id']
        with self.assertRaises(HTTPException) as cm:
            a.remove_group(self.db, 'admin', self.p1, group_id)
        self.assertEqual(cm.exception.status_code, 409)

    def test_cannot_delete_project_with_hosts(self):
        with self.assertRaises(HTTPException) as cm:
            a.delete_empty_project(self.db, 'admin', self.p2)
        self.assertEqual(cm.exception.status_code, 409)

    def test_same_group_can_be_assigned_to_two_projects(self):
        a.add_group(self.db, 'admin', self.p2,
                    {'sid': SID_A, 'sam':'GG_PrjAlphaMaint',
                     'cn':'Project Alpha Maintenance', 'dn':'CN=A'})
        self.assertEqual(self.hosts([(SID_A, 'gg_prjalphamaint')]), {'2','3','4'})

    def test_revoked_membership_changes_visibility_immediately(self):
        user = self.rights([(SID_A, 'gg_prjalphamaint')])
        self.assertEqual(user['scope'], 'project')
        with self.assertRaises(HTTPException):
            self.rights([])

    def test_unsafe_feature_disable_refuses_restart(self):
        with patch.dict(os.environ, {'PORTAL_PROJECT_RBAC':'0'}):
            with self.assertRaises(RuntimeError):
                a.refuse_unsafe_disable(self.db)

    def test_legacy_flag_preserves_old_scope(self):
        with patch.dict(os.environ, {'PORTAL_PROJECT_RBAC':'0'}):
            self.assertEqual(set(a.filter_hosts(self.db, {'scope':'legacy'}, HOSTS)), set(HOSTS))

if __name__ == '__main__':
    unittest.main()
