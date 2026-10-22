import contextlib
import copy
import io
import unittest
from unittest.mock import Mock, patch

import fixtures as f


def database():
    tenants = [{'id': 'tenant-id-' + slug, 'slug': slug, 'status': 'ACTIVE'} for slug in ('acme', 'globex')]
    return {
        'tenants': tenants,
        'memberships': [{'principal_id': user, 'slug': slug, 'status': 'ACTIVE',
                         'principal_status': 'ACTIVE', 'tenant_status': 'ACTIVE'}
                        for user, slug in [(f.ALICE, 'acme'), (f.BOB, 'globex')]],
        'projects': [{'id': p[0], 'tenant_id': 'tenant-id-' + p[1], 'name': p[2]} for p in f.PROJECTS],
        'documents': [{'id': d[0], 'tenant_id': 'tenant-id-' + d[1], 'project_id': d[2],
                       'name': d[3], 'classification': 'INTERNAL'} for d in f.DOCUMENTS],
    }


def relationships(db):
    desired, _, _ = f.reconcile(db, [])
    return [dict(zip(('user', 'relation', 'object'), item)) for item in sorted(desired)]


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.tuples = relationships(self.db)

    def test_consistent_fixtures_and_no_private_grant(self):
        desired, missing, conflicts = f.reconcile(self.db, self.tuples)
        self.assertEqual(9, len(desired))
        self.assertEqual([], missing)
        self.assertEqual([], conflicts)
        self.assertFalse(any(t['object'] == 'project:' + f.PROJECTS[1][0] and t['relation'] == 'viewer'
                             for t in self.tuples))

    def test_missing_project_and_document_links(self):
        for relation in ('tenant', 'parent'):
            with self.subTest(relation=relation):
                tuples = [t for t in self.tuples if t['relation'] != relation]
                _, missing, conflicts = f.reconcile(self.db, tuples)
                self.assertTrue(any(' ' + relation + ' ' in m for m in missing))
                self.assertEqual([], conflicts)

    def test_incorrect_and_multiple_ownership_blocks_all_writes(self):
        for relation in ('tenant', 'parent'):
            for multiple in (False, True):
                with self.subTest(relation=relation, multiple=multiple):
                    tuples = copy.deepcopy(self.tuples)
                    original = next(t for t in tuples if t['relation'] == relation)
                    wrong = dict(original, user='tenant:wrong' if relation == 'tenant' else 'project:wrong')
                    if not multiple:
                        tuples.remove(original)
                    tuples.append(wrong)
                    _, _, conflicts = f.reconcile(self.db, tuples)
                    self.assertTrue(any('Incorrect ownership' in c for c in conflicts))
                    self.assertEqual(multiple, any('Multiple ownership' in c for c in conflicts))
                    api = Mock()
                    with patch.object(f, 'snapshot', return_value=self.db), \
                         patch.object(f, 'read_tuples', return_value=tuples), patch.object(f, 'seed') as seed, \
                         contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(ValueError, 'blocked by conflicts'):
                            f.run('provision', api, 'store', 'model')
                        seed.assert_not_called()
                        api.request.assert_not_called()

    def test_stale_memberships_for_every_inactive_status_and_missing_row(self):
        for status in ('status', 'principal_status', 'tenant_status', 'missing'):
            with self.subTest(status=status):
                db = copy.deepcopy(self.db)
                if status == 'missing':
                    db['memberships'].pop(0)
                else:
                    db['memberships'][0][status] = 'DISABLED'
                _, _, conflicts = f.reconcile(db, self.tuples)
                self.assertTrue(any('Stale/unsupported membership' in c for c in conflicts))

    def test_database_ownership_conflict(self):
        for kind, field in [('projects', 'tenant_id'), ('documents', 'tenant_id'), ('documents', 'project_id')]:
            db = copy.deepcopy(self.db)
            db[kind][0][field] = 'wrong'
            _, _, conflicts = f.reconcile(db, self.tuples)
            self.assertTrue(any('PostgreSQL ownership conflict' in c for c in conflicts))

    def test_unexpected_private_or_cross_tenant_grants_are_conflicts(self):
        for obj in ('project:' + f.PROJECTS[1][0], 'document:' + f.DOCUMENTS[1][0]):
            _, _, conflicts = f.reconcile(self.db, self.tuples + [
                {'user': 'user:' + f.ALICE, 'relation': 'viewer', 'object': obj}])
            self.assertTrue(any('Unexpected resource grant' in c for c in conflicts))

    def test_audit_never_seeds_or_writes(self):
        api = Mock()
        with patch.object(f, 'snapshot', return_value=self.db), \
             patch.object(f, 'read_tuples', return_value=self.tuples), patch.object(f, 'seed') as seed, \
             patch.object(f, 'checks'), contextlib.redirect_stdout(io.StringIO()):
            f.run('audit', api, 'store', 'model')
            seed.assert_not_called()
            api.request.assert_not_called()

    def test_rerun_does_not_write_existing_tuples(self):
        api = Mock()
        with patch.object(f, 'snapshot', return_value=self.db), \
             patch.object(f, 'read_tuples', return_value=self.tuples), patch.object(f, 'seed'), \
             patch.object(f, 'checks'), contextlib.redirect_stdout(io.StringIO()):
            f.run('provision', api, 'store', 'model')
            api.request.assert_not_called()

    def test_read_pagination(self):
        api = Mock()
        api.request.side_effect = [
            {'tuples': [{'key': {'user': 'user:' + f.ALICE, 'relation': 'member', 'object': 'tenant:acme'}}],
             'continuation_token': 'next'}, {'tuples': [], 'continuation_token': ''}
        ] + [{'tuples': [], 'continuation_token': ''}] * 6
        self.assertEqual(1, len(f.read_tuples(api, 'store')))
        self.assertEqual('next', api.request.call_args_list[1].args[1]['continuation_token'])


if __name__ == '__main__':
    unittest.main()
