"""Offline Keycloak 26 provisioning tests. No HTTP or container access."""
import contextlib
import copy
import io
from pathlib import Path
import types
import unittest
from unittest.mock import patch

module = types.ModuleType('machine_keycloak')
source = Path(__file__).with_name('configure-machine-keycloak.py')
exec(compile(source.read_text(), str(source), 'exec'), module.__dict__)


def role(name, client=False, container='realm-id', composite=False):
    return dict(id=name + '-id', name=name, clientRole=client,
                containerId=container, composite=composite)


class Keycloak26:
    """Model relevant REST state, including server-created defaults and lost replies."""
    def __init__(self):
        self.entry = None
        self.account_id = 'service-account-id'
        self.account_generation = 0
        self.secret = 'unchanged-test-secret'
        self.maps = []
        self.roles = []
        self.scope_roles = {}
        self.default = role('default-roles-iam-reference', composite=True)
        self.children = {self.default['id']: [role('offline_access'), role('uma_authorization'),
            role('view-profile', True, 'account-id'), role('manage-account', True, 'account-id', True)],
            'manage-account-id': [role('manage-account-links', True, 'account-id')]}
        self.assigned = {'realmMappings': [self.default]}
        self.defaults = [{'name': 'basic', 'id': 'basic-id'}]
        self.optional = []
        self.basic_maps = [
            {'name': 'sub', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-sub-mapper',
             'config': {'access.token.claim': 'true', 'introspection.token.claim': 'true'}},
            {'name': 'auth_time', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-usersessionmodel-note-mapper',
             'config': {'user.session.note': 'AUTH_TIME', 'claim.name': 'auth_time', 'jsonType.label': 'long',
                        'access.token.claim': 'true', 'id.token.claim': 'true', 'introspection.token.claim': 'true'}}]
        self.basic_roles = {}
        self.groups = []
        self.writes = []
        self.fail_at = None
        self.fail_after = False
        self.inject_final = None

    def realm(self, method, path='', payload=None):
        if method != 'GET':
            self.writes.append((method, path, copy.deepcopy(payload)))
            if self.fail_at == len(self.writes) and not self.fail_after:
                raise module.Failure('Injected request failure')
        result = self.dispatch(method, path, payload)
        if method != 'GET' and self.fail_at == len(self.writes) and self.fail_after:
            raise module.Failure('Injected lost response')
        return copy.deepcopy(result)

    def dispatch(self, method, path, payload):
        if path == '': return {'id': 'realm-id', 'defaultRole': self.default}
        if path == '/clients?clientId=account': return [{'id': 'account-id', 'clientId': 'account'}]
        if path == '/clients?clientId=iam-policy-reader': return [self.entry] if self.entry else []
        if path == '/client-scopes': return self.defaults
        if path == '/client-scopes/basic-id/protocol-mappers/models': return self.basic_maps
        if path == '/client-scopes/basic-id/scope-mappings': return self.basic_roles
        if path.startswith('/roles-by-id/'):
            return self.children.get(path.split('/')[2], [])
        if path == '/clients' and method == 'POST':
            self.entry = dict(payload, id='machine-id')
            # ClientManager automatically adds these three metadata mappers.
            self.maps = [
                {'name': name, 'protocol': 'openid-connect',
                 'protocolMapper': 'oidc-usersessionmodel-note-mapper',
                 'config': {'user.session.note': claim, 'claim.name': claim, 'jsonType.label': 'String',
                            'access.token.claim': 'true', 'id.token.claim': 'true', 'introspection.token.claim': 'true'}}
                for name, claim in [('Client ID', 'client_id'), ('Client Host', 'clientHost'),
                                    ('Client IP Address', 'clientAddress')]]
            return
        if path == '/clients/machine-id':
            if method == 'PUT':
                # Keycloak 26.0.8 deletes the user when this flag is omitted.
                if payload.get('serviceAccountsEnabled') is not True:
                    self.account_id = None
                    self.assigned = {}
                self.entry.update(payload)
                return
            if self.inject_final:
                self.inject_final(self)
                self.inject_final = None
            return self.entry
        if path.endswith('/default-client-scopes'): return self.defaults
        if path.endswith('/optional-client-scopes'): return self.optional
        if path.endswith('/protocol-mappers/models'):
            if method == 'POST': self.maps.append(payload); return
            return self.maps
        if path.endswith('/roles'):
            if method == 'POST': self.roles.append(dict(payload, id='policy-role-id', clientRole=True, containerId='machine-id')); return
            return self.roles
        if path.endswith('/roles/policy.read'): return self.roles[0]
        if path.endswith('/scope-mappings'): return self.scope_roles
        if path.endswith('/service-account-user'):
            if self.account_id is None:
                self.account_generation += 1
                self.account_id = 'recreated-account-' + str(self.account_generation)
                self.assigned = {'realmMappings': [self.default]}
            return {'id': self.account_id}
        if path == '/users/' + str(self.account_id) + '/groups': return self.groups
        if path.endswith('/role-mappings'): return self.assigned
        if '/roles/policy.read/groups?' in path: return []
        if '/roles/policy.read/users?' in path:
            return [{'id': self.account_id}] if self.assigned.get('clientMappings') else []
        if path.endswith('/scope-mappings/clients/machine-id'):
            self.scope_roles = {'clientMappings': {'iam-policy-reader': {'id': 'machine-id', 'client': 'iam-policy-reader', 'mappings': payload}}}
            return
        if path.endswith('/role-mappings/clients/machine-id'):
            self.assigned['clientMappings'] = {'iam-policy-reader': {'id': 'machine-id', 'client': 'iam-policy-reader', 'mappings': payload}}
            return
        raise AssertionError('Unexpected API operation: ' + method + ' ' + path)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        # Fail immediately if a test accidentally reaches the network.
        self.network = patch.object(module.urllib.request.OpenerDirector, 'open', side_effect=AssertionError('Network forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def provision(self, api, resume=False):
        with contextlib.redirect_stdout(io.StringIO()):
            module.provision(api, resume_disabled=resume)

    def complete(self):
        api = Keycloak26()
        self.provision(api)
        return api

    def reject_without_writes(self, api, resume=False):
        before = copy.deepcopy(api.writes)
        with self.assertRaises(module.Failure): self.provision(api, resume)
        self.assertEqual(api.writes, before)

    def repair_fixture(self):
        api = self.complete()
        api.assigned.pop('clientMappings')
        api.writes.clear()
        return api

    def repair(self, api):
        with contextlib.redirect_stdout(io.StringIO()):
            module.repair_missing_role(api)

    def test_repair_success_changes_only_assignment_and_enabled_state(self):
        api = self.repair_fixture()
        before = copy.deepcopy(api.__dict__)
        self.repair(api)
        self.assertTrue(api.entry['enabled'])
        self.assertTrue(module.has_role(api.assigned))
        self.assertEqual([method for method, _, _ in api.writes], ['PUT', 'POST', 'PUT'])
        self.assertEqual(api.writes[0][2], {'enabled': False, 'serviceAccountsEnabled': True})
        self.assertEqual(api.writes[1][1], '/users/service-account-id/role-mappings/clients/machine-id')
        self.assertEqual(api.writes[1][2], [before['roles'][0]])
        for key in ('entry', 'secret', 'maps', 'roles', 'scope_roles', 'defaults', 'optional', 'default', 'children'):
            self.assertEqual(api.__dict__[key], before[key])
        self.assertEqual(api.assigned['realmMappings'], before['assigned']['realmMappings'])

    def test_repair_assignment_is_exact_expected_delta(self):
        api = self.repair_fixture()
        expected = copy.deepcopy(api.assigned)
        expected['clientMappings'] = {'iam-policy-reader': {
            'id': 'machine-id', 'client': 'iam-policy-reader',
            'mappings': [copy.deepcopy(api.roles[0])]}}
        self.repair(api)
        self.assertEqual(api.assigned, expected)

    def test_repair_final_assignment_comparison_rejects_identity_drift(self):
        mutations = [
            # Same allowed name, different role UUID: inspect alone accepts this.
            lambda a: a.assigned['clientMappings']['iam-policy-reader']['mappings'][0].update(id='other-role-id'),
            lambda a: a.assigned['clientMappings']['iam-policy-reader'].update(id='other-client-id'),
            lambda a: a.assigned['clientMappings']['iam-policy-reader'].update(client='other-client'),
            # Duplicate allowed role still passes has_role/check_mappings.
            lambda a: a.assigned['clientMappings']['iam-policy-reader']['mappings'].append(copy.deepcopy(a.roles[0])),
            lambda a: a.assigned['realmMappings'][0].update(description='changed'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                api = self.repair_fixture()
                original = api.dispatch
                def dispatch(method, path, payload):
                    result = original(method, path, payload)
                    if method == 'POST' and '/role-mappings/clients/' in path:
                        # Detach assignments from fixture's shared role objects.
                        api.assigned = copy.deepcopy(api.assigned)
                        mutate(api)
                    return result
                api.dispatch = dispatch
                # Exact assignment persistence rejects identity drift before enabling.
                with patch.object(module, 'inspect', wraps=module.inspect) as inspected:
                    with self.assertRaisesRegex(module.Failure, 'confirmed disabled'):
                        self.repair(api)
                    self.assertFalse(any(c.kwargs.get('complete') for c in inspected.call_args_list))
                self.assertFalse(api.entry['enabled'])
                self.assertFalse(any(payload == {'enabled': True, 'serviceAccountsEnabled': True} for _, _, payload in api.writes))

    def test_repair_rejects_additional_client_or_realm_assignment(self):
        mutations = [
            lambda a: a.assigned['clientMappings'].update({'other': {
                'id': 'other-id', 'client': 'other', 'mappings': [role('admin', True, 'other-id')]}}),
            lambda a: a.assigned['realmMappings'].append(role('extra-realm-role')),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                api = self.repair_fixture()
                original = api.dispatch
                def dispatch(method, path, payload):
                    result = original(method, path, payload)
                    if method == 'POST' and '/role-mappings/clients/' in path:
                        mutate(api)
                    return result
                api.dispatch = dispatch
                with self.assertRaises(module.Failure): self.repair(api)
                self.assertFalse(api.entry['enabled'])
                self.assertFalse(any(payload == {'enabled': True, 'serviceAccountsEnabled': True} for _, _, payload in api.writes))

    def test_disabled_repair_success_preserves_resources(self):
        api = self.repair_fixture(); api.entry['enabled'] = False
        before = copy.deepcopy(api.__dict__)
        self.repair(api)
        self.assertTrue(api.entry['enabled'])
        self.assertTrue(module.has_role(api.assigned))
        self.assertEqual([m for m, _, _ in api.writes], ['POST', 'PUT'])
        for key in ('secret', 'maps', 'roles', 'scope_roles', 'defaults', 'optional', 'default', 'children'):
            self.assertEqual(api.__dict__[key], before[key])
        self.assertEqual(api.entry['id'], before['entry']['id'])

    def test_assignment_request_failure_is_read_back_not_retried(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                api = self.repair_fixture(); api.entry['enabled'] = False
                api.fail_at = 1; api.fail_after = committed
                with self.assertRaises(module.Failure) as caught: self.repair(api)
                message = str(caught.exception)
                self.assertIn('direct role-assignment request', message)
                self.assertIn('exact assignment confirmed' if committed else 'assignment unchanged', message)
                self.assertEqual(sum(m == 'POST' for m, _, _ in api.writes), 1)
                self.assertEqual(module.has_role(api.assigned), committed)
                self.assertFalse(api.entry['enabled'])

    def test_assignment_not_persisted_reports_persistence_stage(self):
        api = self.repair_fixture(); api.entry['enabled'] = False
        original = api.dispatch
        def dispatch(method, path, payload):
            if method == 'POST' and '/role-mappings/clients/' in path: return None
            return original(method, path, payload)
        api.dispatch = dispatch
        with self.assertRaisesRegex(module.Failure, 'assignment persistence verification'):
            self.repair(api)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(p == {'enabled': True, 'serviceAccountsEnabled': True} for _, _, p in api.writes))

    def test_sanitized_stages_for_preflight_disable_and_enable(self):
        for stage, write in [('client disable and confirmation', 1),
                             ('client re-enable and confirmation', 3)]:
            with self.subTest(stage=stage):
                api = self.repair_fixture(); api.fail_at = write
                with self.assertRaisesRegex(module.Failure, stage): self.repair(api)
                self.assertFalse(api.entry['enabled'])
        api = self.repair_fixture(); api.entry['enabled'] = False
        with patch.object(module, 'inspect', side_effect=RuntimeError('PASSWORD TOKEN SECRET BODY')):
            with self.assertRaises(module.Failure) as caught: self.repair(api)
        self.assertIn('initial preflight', str(caught.exception))
        self.assertNotIn('PASSWORD', str(caught.exception))
        self.assertEqual(api.writes, [])
        self.assertFalse(api.entry['enabled'])

    def test_pre_assignment_comparison_stage(self):
        api = self.repair_fixture()
        original = api.dispatch
        def dispatch(method, path, payload):
            result = original(method, path, payload)
            if method == 'PUT' and payload == {'enabled': False, 'serviceAccountsEnabled': True}:
                api.entry['description'] = 'concurrent change'
            return result
        api.dispatch = dispatch
        with self.assertRaisesRegex(module.Failure, 'pre-assignment configuration comparison'):
            self.repair(api)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(m == 'POST' for m, _, _ in api.writes))

    def test_complete_and_final_stages_are_sanitized(self):
        for fail_complete in (True, False):
            with self.subTest(fail_complete=fail_complete):
                api = self.repair_fixture(); api.entry['enabled'] = False
                original = module.inspect
                def inspect(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if kwargs.get('complete'):
                        if fail_complete: raise RuntimeError('PASSWORD TOKEN SECRET BODY')
                        # Change occurs after persistence/complete validation, before final snapshot.
                        api.entry['description'] = 'changed'
                    return result
                with patch.object(module, 'inspect', side_effect=inspect):
                    with self.assertRaises(module.Failure) as caught: self.repair(api)
                message = str(caught.exception)
                self.assertIn('complete configuration validation' if fail_complete else 'final configuration comparison', message)
                for sensitive in ('PASSWORD', 'TOKEN', 'SECRET', 'BODY'):
                    self.assertNotIn(sensitive, message)
                self.assertFalse(api.entry['enabled'])
                self.assertFalse(any(p == {'enabled': True, 'serviceAccountsEnabled': True} for _, _, p in api.writes))

    def test_disabled_repair_rejects_present_role_without_writes(self):
        api = self.complete(); api.entry['enabled'] = False; api.writes.clear()
        with self.assertRaisesRegex(module.Failure, 'initial preflight'): self.repair(api)
        self.assertEqual(api.writes, [])
        self.assertFalse(api.entry['enabled'])

    def test_repair_assignment_normalization_is_narrow(self):
        expected = {'realmMappings': [role('existing')], 'clientMappings': {
            'iam-policy-reader': {'id': 'machine-id', 'client': 'iam-policy-reader',
                                 'mappings': [role('policy.read', True, 'machine-id')]}}}
        role_id = 'policy.read-id'
        def matches(actual, wanted=expected):
            return module.repair_assignments_match(actual, wanted, 'machine-id', role_id)
        self.assertTrue(matches(expected))
        empty = copy.deepcopy(expected)
        empty['clientMappings']['iam-policy-reader']['mappings'][0]['attributes'] = {}
        self.assertTrue(matches(empty))
        self.assertTrue(matches(expected, empty))
        self.assertNotIn('attributes', expected['clientMappings']['iam-policy-reader']['mappings'][0])
        for field, value in [('id', 'wrong'), ('name', 'other'), ('containerId', 'wrong'),
                             ('clientRole', False), ('composite', True),
                             ('attributes', {'permission': ['extra']}), ('attributes', None),
                             ('description', 'changed'), ('unknown', {})]:
            with self.subTest(field=field, value=value):
                actual = copy.deepcopy(expected)
                actual['clientMappings']['iam-policy-reader']['mappings'][0][field] = value
                self.assertFalse(matches(actual))
        for mutation in (
            lambda a: a['clientMappings']['iam-policy-reader'].update(id='wrong'),
            lambda a: a['clientMappings']['iam-policy-reader']['mappings'].append(role('extra')),
            lambda a: a['clientMappings'].update({'other': {'mappings': []}}),
            lambda a: a['clientMappings'].clear(),
            lambda a: a['realmMappings'][0].update(attributes={}),
        ):
            actual = copy.deepcopy(expected); mutation(actual)
            self.assertFalse(matches(actual))

    def test_disabled_repair_accepts_empty_attributes_on_added_role_only(self):
        api = self.repair_fixture(); api.entry['enabled'] = False
        original = api.dispatch
        def dispatch(method, path, payload):
            result = original(method, path, payload)
            if method == 'GET' and path == '/users/service-account-id/role-mappings':
                result = copy.deepcopy(result)
                for mapping in result.get('clientMappings', {}).values():
                    for assigned in mapping['mappings']:
                        assigned['attributes'] = {}
            return result
        api.dispatch = dispatch
        self.repair(api)
        self.assertTrue(api.entry['enabled'])
        self.assertTrue(module.has_role(api.assigned))
        self.assertEqual(sum(m == 'POST' for m, _, _ in api.writes), 1)

    def test_keycloak26_mock_reproduces_unsafe_put_deletion(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                api = self.complete()
                original_id = api.account_id
                api.realm('PUT', '/clients/machine-id', {'enabled': enabled})
                self.assertIsNone(api.account_id)
                account = api.realm('GET', '/clients/machine-id/service-account-user')
                self.assertNotEqual(account['id'], original_id)
                self.assertFalse(module.has_role(api.assigned))

    def test_all_enabled_updates_preserve_service_account_flag_and_identity(self):
        for start_enabled in (False, True):
            for fail_at in (None, 1, 2, 3):
                with self.subTest(enabled=start_enabled, fail_at=fail_at):
                    api = self.repair_fixture()
                    api.entry['enabled'] = start_enabled
                    original_id = api.account_id
                    api.fail_at = fail_at
                    try:
                        self.repair(api)
                    except module.Failure:
                        pass
                    for method, _, payload in api.writes:
                        if method == 'PUT':
                            self.assertIs(payload['serviceAccountsEnabled'], True)
                    self.assertEqual(api.account_id, original_id)
                    self.assertEqual(api.account_generation, 0)
        api = self.complete()
        self.assertEqual(api.account_id, 'service-account-id')
        self.assertTrue(module.has_role(api.assigned))
        self.assertEqual(api.account_generation, 0)
        self.assertTrue(all(p.get('serviceAccountsEnabled') is True
                            for m, _, p in api.writes if m == 'PUT'))

    def test_post_enable_validation_detects_assignment_loss_or_identity_change(self):
        for identity_change in (False, True):
            with self.subTest(identity_change=identity_change):
                api = self.repair_fixture(); api.entry['enabled'] = False
                original = api.dispatch
                def dispatch(method, path, payload):
                    result = original(method, path, payload)
                    if method == 'PUT' and payload.get('enabled') is True:
                        if identity_change:
                            # Keep roles intact to prove the UUID guard itself fires.
                            api.account_id = 'unexpected-account'
                        else:
                            api.assigned.pop('clientMappings', None)
                    return result
                api.dispatch = dispatch
                with self.assertRaisesRegex(module.Failure, 'client re-enable and confirmation'):
                    self.repair(api)
                self.assertFalse(api.entry['enabled'])
                self.assertEqual(api.account_generation, 0)

    def test_repair_write_failures_leave_disabled(self):
        for position in (1, 2, 3):
            for after in (False, True):
                with self.subTest(position=position, after=after):
                    api = self.repair_fixture(); api.fail_at = position; api.fail_after = after
                    with self.assertRaises(module.Failure): self.repair(api)
                    self.assertFalse(api.entry['enabled'])
                    if position < 3:
                        self.assertFalse(any(payload == {'enabled': True, 'serviceAccountsEnabled': True} for _, _, payload in api.writes))

    def test_repair_final_validation_failure_never_enables(self):
        api = self.repair_fixture()
        original = module.inspect
        def validate(*args, **kwargs):
            if kwargs.get('complete'): raise module.Failure('Injected validation failure')
            return original(*args, **kwargs)
        with patch.object(module, 'inspect', side_effect=validate):
            with self.assertRaises(module.Failure): self.repair(api)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(payload == {'enabled': True, 'serviceAccountsEnabled': True} for _, _, payload in api.writes))

    def test_repair_rejects_unexpected_preexisting_configuration_without_writes(self):
        for change in (lambda a: a.entry.update(fullScopeAllowed=True),
                       lambda a: a.maps.pop(), lambda a: a.scope_roles.clear(),
                       lambda a: a.assigned['realmMappings'].append(role('admin'))):
            api = self.repair_fixture(); change(api)
            with self.assertRaises(module.Failure): self.repair(api)
            self.assertEqual(api.writes, [])

    def test_repair_rejects_drift_after_disable(self):
        api = self.repair_fixture()
        original = api.dispatch
        def dispatch(method, path, payload):
            result = original(method, path, payload)
            if method == 'PUT' and payload == {'enabled': False, 'serviceAccountsEnabled': True}:
                api.maps[0]['config']['claim.name'] = 'aud'
            return result
        api.dispatch = dispatch
        with self.assertRaises(module.Failure): self.repair(api)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(method == 'POST' for method, _, _ in api.writes))

    def test_repair_reports_when_disabling_cannot_be_confirmed(self):
        api = self.repair_fixture()
        original = api.realm
        def unavailable(method, path='', payload=None):
            if method == 'PUT': raise module.Failure('Unavailable')
            return original(method, path, payload)
        api.realm = unavailable
        with self.assertRaisesRegex(module.Failure, 'disabled state could not be confirmed'):
            self.repair(api)
        self.assertFalse(module.has_role(api.assigned))

    def test_stock_defaults_preserved_and_repeat_is_read_only(self):
        api = self.complete()
        self.assertTrue(api.entry['enabled'])
        self.assertEqual(api.assigned['realmMappings'], [api.default])
        self.assertEqual(len(api.maps), 5)
        self.assertEqual(len(api.roles), 1)
        before = copy.deepcopy(api.__dict__)
        self.provision(api)
        self.assertEqual(api.__dict__, before)
        self.assertTrue(all(method != 'DELETE' and 'secret' not in path for method, path, _ in api.writes))

    def test_no_realm_roles_also_supported(self):
        api = Keycloak26(); api.assigned = {}
        self.provision(api)
        self.assertTrue(api.entry['enabled'])

    def test_reject_unexpected_direct_realm_role(self):
        api = self.complete(); api.assigned['realmMappings'].append(role('admin'))
        self.reject_without_writes(api)

    def test_reject_unexpected_nested_default_permission(self):
        api = self.complete()
        api.children['manage-account-id'].append(role('realm-admin', True, 'realm-management-id'))
        self.reject_without_writes(api)

    def test_reject_spoofed_default_role_id(self):
        api = self.complete(); api.assigned['realmMappings'] = [dict(api.default, id='spoofed')]
        self.reject_without_writes(api)

    def test_missing_each_expected_nested_role_is_rejected(self):
        for parent, child in [
            ('default-roles-iam-reference-id', 'offline_access'),
            ('default-roles-iam-reference-id', 'uma_authorization'),
            ('default-roles-iam-reference-id', 'view-profile'),
            ('default-roles-iam-reference-id', 'manage-account'),
            ('manage-account-id', 'manage-account-links'),
        ]:
            with self.subTest(child=child):
                api = self.complete()
                api.children[parent] = [r for r in api.children[parent] if r['name'] != child]
                self.reject_without_writes(api)

    def test_same_expanded_roles_with_changed_edges_are_rejected(self):
        api = self.complete()
        # Preserve all six roles, but move the nested role to the root.
        api.children[api.default['id']].extend(api.children.pop('manage-account-id'))
        self.reject_without_writes(api)

    def test_modified_role_metadata_is_rejected(self):
        for field, value in [('clientRole', True), ('containerId', 'other-realm'),
                             ('composite', False), ('name', 'different-default')]:
            with self.subTest(root_field=field):
                api = self.complete(); api.default[field] = value
                self.reject_without_writes(api)
        for field, value in [('clientRole', False), ('containerId', 'other-client'),
                             ('composite', True), ('id', 'offline_access-id')]:
            with self.subTest(nested_field=field):
                api = self.complete()
                api.children['manage-account-id'][0][field] = value
                self.reject_without_writes(api)

    def test_additional_edge_and_hidden_leaf_children_are_rejected(self):
        api = self.complete()
        api.children[api.default['id']].append(role('manage-account-links', True, 'account-id'))
        self.reject_without_writes(api)
        api = self.complete()
        api.children['offline_access-id'] = [role('admin')]
        self.reject_without_writes(api)

    def test_reject_scopes_mappers_groups_and_role_conflicts(self):
        mutations = [
            lambda a: a.defaults.append({'name': 'roles', 'id': 'roles-id'}),
            lambda a: a.optional.append({'name': 'offline_access'}),
            lambda a: a.basic_maps.append(module.mappers()[0]),
            lambda a: a.basic_roles.update(realmMappings=[role('offline_access')]),
            lambda a: a.maps[0]['config'].update({'claim.name': 'realm_access.roles'}),
            lambda a: a.groups.append({'id': 'human-group'}),
            lambda a: a.assigned['clientMappings'].update({'other': {'mappings': [role('admin')]}}),
            lambda a: a.scope_roles.update(realmMappings=[role('offline_access')]),
            lambda a: a.entry.update(fullScopeAllowed=True),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                api = self.complete(); mutate(api); self.reject_without_writes(api)

    def check_basic_read_only(self, api, accepted):
        before = copy.deepcopy(api.__dict__)
        if accepted:
            module.check_basic_scope(api, api.defaults[0])
        else:
            with self.assertRaises(module.Failure):
                module.check_basic_scope(api, api.defaults[0])
        self.assertEqual(api.__dict__, before)

    def test_basic_userinfo_absent_accepted(self):
        self.check_basic_read_only(Keycloak26(), accepted=True)

    def test_basic_userinfo_true_accepted(self):
        api = Keycloak26()
        api.basic_maps[1]['config']['userinfo.token.claim'] = 'true'
        self.check_basic_read_only(api, accepted=True)
        self.provision(api)
        before = copy.deepcopy(api.__dict__)
        self.provision(api)
        self.assertEqual(api.__dict__, before)

    def test_basic_userinfo_false_rejected(self):
        api = Keycloak26()
        api.basic_maps[1]['config']['userinfo.token.claim'] = 'false'
        self.check_basic_read_only(api, accepted=False)

    def test_basic_unknown_config_field_rejected(self):
        api = Keycloak26()
        api.basic_maps[1]['config'].update({'userinfo.token.claim': 'true', 'unexpected': 'true'})
        self.check_basic_read_only(api, accepted=False)

    def test_basic_additional_mapper_rejected(self):
        api = Keycloak26()
        api.basic_maps.append(module.mappers()[0])
        self.check_basic_read_only(api, accepted=False)

    def test_basic_userinfo_exception_does_not_apply_to_sub(self):
        api = Keycloak26()
        api.basic_maps[0]['config']['userinfo.token.claim'] = 'true'
        self.check_basic_read_only(api, accepted=False)

    def test_basic_userinfo_variant_still_rejects_modified_claim(self):
        api = Keycloak26()
        api.basic_maps[1]['config'].update({'userinfo.token.claim': 'true', 'claim.name': 'aud'})
        self.check_basic_read_only(api, accepted=False)

    def test_basic_userinfo_variant_still_rejects_role_scope_mappings(self):
        for mappings in ({'realmMappings': [role('offline_access')]},
                         {'clientMappings': {'other': {'mappings': [role('admin')]}}}):
            with self.subTest(mappings=mappings):
                api = Keycloak26()
                api.basic_maps[1]['config']['userinfo.token.claim'] = 'true'
                api.basic_roles = mappings
                self.check_basic_read_only(api, accepted=False)

    def test_missing_basic_fails_before_creation(self):
        api = Keycloak26(); api.defaults = []
        self.reject_without_writes(api)
        self.assertIsNone(api.entry)

    def test_service_mapper_userinfo_absent_and_true_accepted(self):
        for name in ('Client ID', 'Client Host', 'Client IP Address'):
            for explicit in (False, True):
                with self.subTest(mapper=name, explicit=explicit):
                    api = self.complete()
                    mapper = next(m for m in api.maps if m['name'] == name)
                    if explicit:
                        mapper['config']['userinfo.token.claim'] = 'true'
                    before = copy.deepcopy(api.__dict__)
                    self.provision(api)
                    self.assertEqual(api.__dict__, before)

    def test_service_mapper_userinfo_false_and_unknown_fields_rejected(self):
        for name in ('Client ID', 'Client Host', 'Client IP Address'):
            for change in ({'userinfo.token.claim': 'false'},
                           {'userinfo.token.claim': 'true', 'unexpected': 'true'}):
                with self.subTest(mapper=name, change=change):
                    api = self.complete()
                    next(m for m in api.maps if m['name'] == name)['config'].update(change)
                    self.reject_without_writes(api)

    def test_service_mapper_variant_does_not_accept_other_changes(self):
        changes = [
            ('name', 'Unexpected Mapper'), ('protocolMapper', 'oidc-hardcoded-claim-mapper'),
            ('protocol', 'saml'), ('claim.name', 'aud'), ('user.session.note', 'other'),
            ('access.token.claim', 'false'), ('introspection.token.claim', 'false'),
            ('id.token.claim', 'false'), ('jsonType.label', 'long'),
        ]
        for name in ('Client ID', 'Client Host', 'Client IP Address'):
            for field, value in changes:
                with self.subTest(mapper=name, field=field):
                    api = self.complete()
                    mapper = next(m for m in api.maps if m['name'] == name)
                    mapper['config']['userinfo.token.claim'] = 'true'
                    target = mapper if field in ('name', 'protocolMapper', 'protocol') else mapper['config']
                    target[field] = value
                    self.reject_without_writes(api)

    def test_owned_mappers_do_not_receive_service_mapper_exception(self):
        for name in ('machine-api-audience', 'machine-policy-role'):
            for field in ('userinfo.token.claim', 'unexpected'):
                with self.subTest(mapper=name, field=field):
                    api = self.complete()
                    next(m for m in api.maps if m['name'] == name)['config'][field] = 'true'
                    self.reject_without_writes(api)

    def effective_owned_mappers(self):
        # Independent fixture matching the read-only Keycloak 26.0.8 diagnosis.
        return [
            {'name': 'machine-api-audience', 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-audience-mapper', 'config': {
                 'included.custom.audience': 'iam-machine-api', 'access.token.claim': 'true',
                 'id.token.claim': 'false', 'introspection.token.claim': 'true',
                 'userinfo.token.claim': 'false'}},
            {'name': 'machine-policy-role', 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-usermodel-client-role-mapper', 'config': {
                 'usermodel.clientRoleMapping.clientId': 'iam-policy-reader',
                 'claim.name': 'resource_access.iam-policy-reader.roles', 'jsonType.label': 'String',
                 'multivalued': 'true', 'access.token.claim': 'true', 'id.token.claim': 'false',
                 'userinfo.token.claim': 'false', 'introspection.token.claim': 'true'}},
        ]

    def test_effective_owned_mappers_pass_and_enabled_repeat_is_read_only(self):
        api = self.complete()
        api.maps = api.maps[:3] + self.effective_owned_mappers()
        before = copy.deepcopy(api.__dict__)
        self.provision(api)
        self.assertEqual(api.__dict__, before)

    def test_effective_owned_mapper_settings_remain_exact(self):
        for name in ('machine-api-audience', 'machine-policy-role'):
            changes = [('introspection.token.claim', 'false'), ('userinfo.token.claim', 'true'),
                       ('unknown', 'true'), ('access.token.claim', 'false')]
            changes.append(('included.custom.audience', 'iam-api') if name == 'machine-api-audience'
                           else ('claim.name', 'realm_access.roles'))
            for field, value in changes:
                with self.subTest(mapper=name, field=field):
                    api = self.complete()
                    api.maps = api.maps[:3] + self.effective_owned_mappers()
                    next(m for m in api.maps if m['name'] == name)['config'][field] = value
                    self.reject_without_writes(api)

    def test_effective_owned_mapper_defaults_cannot_be_missing(self):
        for name, fields in [('machine-api-audience', ('introspection.token.claim', 'userinfo.token.claim')),
                             ('machine-policy-role', ('introspection.token.claim',))]:
            for field in fields:
                with self.subTest(mapper=name, field=field):
                    api = self.complete()
                    del next(m for m in api.maps if m['name'] == name)['config'][field]
                    self.reject_without_writes(api)

    def test_disabled_client_with_effective_owned_mappers_recovers_safely(self):
        api = self.partial_service_variant()
        api.maps.extend(self.effective_owned_mappers())
        original_id, original_secret = api.entry['id'], api.secret
        self.reject_without_writes(api)
        self.assertFalse(api.entry['enabled'])
        self.provision(api, resume=True)
        self.assertTrue(api.entry['enabled'])
        self.assertEqual((api.entry['id'], api.secret), (original_id, original_secret))
        self.assertEqual(len(api.maps), 5)
        self.assertEqual(len(api.roles), 1)
        before = copy.deepcopy(api.__dict__)
        self.provision(api)
        self.assertEqual(api.__dict__, before)

    def test_effective_owned_mapper_drift_blocks_final_enable(self):
        api = self.partial_service_variant()
        api.maps.extend(self.effective_owned_mappers())
        api.inject_final = lambda a: a.maps[-1]['config'].update({'introspection.token.claim': 'false'})
        with self.assertRaises(module.Failure): self.provision(api, resume=True)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(method == 'PUT' for method, _, _ in api.writes))

    def partial_service_variant(self):
        api = Keycloak26()
        # Simulate interruption immediately after creation committed, without a reply.
        api.fail_at = 1; api.fail_after = True
        with self.assertRaises(module.Failure): self.provision(api)
        api.fail_at = None
        for mapper in api.maps:
            mapper['config']['userinfo.token.claim'] = 'true'
        return api

    def test_disabled_service_variant_requires_explicit_safe_recovery(self):
        api = self.partial_service_variant()
        original_id, original_secret = api.entry['id'], api.secret
        self.reject_without_writes(api)
        self.assertFalse(api.entry['enabled'])
        self.provision(api, resume=True)
        self.assertTrue(api.entry['enabled'])
        self.assertEqual((api.entry['id'], api.secret), (original_id, original_secret))
        self.assertEqual(len(api.maps), 5)
        self.assertEqual(len(api.roles), 1)
        before = copy.deepcopy(api.__dict__)
        self.provision(api)
        self.assertEqual(api.__dict__, before)

    def test_disabled_service_variant_rechecks_before_enable(self):
        api = self.partial_service_variant()
        api.inject_final = lambda a: a.maps[0]['config'].update({'userinfo.token.claim': 'false'})
        with self.assertRaises(module.Failure): self.provision(api, resume=True)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(method == 'PUT' for method, _, _ in api.writes))

    def test_existing_disabled_requires_explicit_resume(self):
        api = self.complete(); api.entry['enabled'] = False
        self.reject_without_writes(api)
        self.provision(api, resume=True)
        self.assertTrue(api.entry['enabled'])

    def test_enabled_incomplete_is_not_repaired(self):
        api = self.complete(); api.maps.pop()
        self.reject_without_writes(api)

    def test_failure_before_and_after_every_write_resumes(self):
        count = len(self.complete().writes)
        for after in (False, True):
            for position in range(1, count + 1):
                with self.subTest(after=after, position=position):
                    api = Keycloak26(); api.fail_at = position; api.fail_after = after
                    with self.assertRaises(module.Failure): self.provision(api)
                    if api.entry and not (after and position == count):
                        self.assertFalse(api.entry['enabled'])
                    api.fail_at = None
                    self.provision(api, resume=True)
                    self.assertTrue(api.entry['enabled'])
                    self.assertEqual(api.entry['id'], 'machine-id')
                    self.assertEqual(api.secret, 'unchanged-test-secret')
                    self.assertEqual(len(api.roles), 1)
                    self.assertEqual(len(api.maps), 5)
                    self.assertEqual(sum(path == '/clients' for _, path, _ in api.writes),
                                     2 if position == 1 and not after else 1)

    def test_resume_rejects_unsafe_disabled_client(self):
        api = self.complete(); api.entry['enabled'] = False
        api.children['manage-account-id'].append(role('realm-admin', True, 'realm-management-id'))
        self.reject_without_writes(api, resume=True)
        self.assertFalse(api.entry['enabled'])

    def test_final_revalidation_prevents_enable_after_permission_drift(self):
        api = Keycloak26()
        api.inject_final = lambda a: a.assigned['realmMappings'].append(role('admin'))
        with self.assertRaises(module.Failure): self.provision(api)
        self.assertFalse(api.entry['enabled'])
        self.assertFalse(any(method == 'PUT' for method, _, _ in api.writes))


if __name__ == '__main__':
    unittest.main()
