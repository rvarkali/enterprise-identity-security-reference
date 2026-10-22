#!/usr/bin/env python3
"""Provision only iam-policy-reader. No automatic credential rotation or role removal."""
import argparse
import copy
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

REALM = 'iam-reference'
CLIENT = 'iam-policy-reader'
AUDIENCE = 'iam-machine-api'
ROLE = 'policy.read'


class Failure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, base, username, password):
        parsed = urllib.parse.urlsplit(base)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or (parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'))):
            raise Failure('Use HTTPS, or HTTP on loopback only; URL credentials are forbidden.')
        self.base = base.rstrip('/')
        self.opener = urllib.request.build_opener(NoRedirect)
        self.token = None
        reply = self.request('POST', '/realms/master/protocol/openid-connect/token', form={
            'client_id': 'admin-cli', 'grant_type': 'password',
            'username': username, 'password': password})
        self.token = reply['access_token']

    def request(self, method, path, payload=None, form=None, admin=False):
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if admin:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=15) as response:
                data = response.read()
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            raise Failure('Keycloak request rejected (HTTP %s); response body suppressed.' % error.code) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise Failure('Keycloak connection or response failure; details suppressed.') from None

    def realm(self, method, path='', payload=None):
        return self.request(method, '/admin/realms/' + REALM + path, payload=payload, admin=True)


def arguments(description, provisioning=False):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--url', default='http://localhost:8081', help='Keycloak URL (default: local port 8081)')
    parser.add_argument('--admin-user', default=os.environ.get('KEYCLOAK_ADMIN', 'admin'))
    if provisioning:
        operation = parser.add_mutually_exclusive_group()
        operation.add_argument('--repair-missing-role', action='store_true',
                               help='Authorize disable, repair only the missing service-account policy.read assignment, validate, and enable')
        operation.add_argument('--resume-disabled', action='store_true',
                            help='Explicitly resume and enable a disabled client after all safety checks pass')
    return parser.parse_args()


def connect(args):
    password = os.environ.get('KEYCLOAK_ADMIN_PASSWORD') or getpass.getpass('Keycloak administrator password: ')
    return API(args.url, args.admin_user, password)


def client(api):
    matches = api.realm('GET', '/clients?clientId=' + CLIENT)
    matches = [entry for entry in matches if entry['clientId'] == CLIENT]
    if len(matches) > 1:
        raise Failure('Conflicting machine client records.')
    return matches[0] if matches else None


def mappers():
    return [
        {'name': 'machine-api-audience', 'protocol': 'openid-connect',
         'protocolMapper': 'oidc-audience-mapper', 'config': {
             'included.custom.audience': AUDIENCE, 'access.token.claim': 'true', 'id.token.claim': 'false',
             'introspection.token.claim': 'true', 'userinfo.token.claim': 'false'}},
        {'name': 'machine-policy-role', 'protocol': 'openid-connect',
         'protocolMapper': 'oidc-usermodel-client-role-mapper', 'config': {
             'usermodel.clientRoleMapping.clientId': CLIENT,
             'claim.name': 'resource_access.' + CLIENT + '.roles',
             'jsonType.label': 'String', 'multivalued': 'true',
             'access.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false',
             'introspection.token.claim': 'true'}},
    ]


def settings():
    return dict(clientId=CLIENT, protocol='openid-connect', publicClient=False,
                bearerOnly=False, clientAuthenticatorType='client-secret',
                serviceAccountsEnabled=True, standardFlowEnabled=False,
                implicitFlowEnabled=False, directAccessGrantsEnabled=False,
                fullScopeAllowed=False, authorizationServicesEnabled=False,
                redirectUris=[], webOrigins=[])


def compatible(actual, expected):
    return all(actual.get(key, False if key == 'authorizationServicesEnabled' else None) == value
               for key, value in expected.items())


def session_mapper(name, claim, json_type='String', note=None):
    # Keycloak 26 ClientManager / OIDCLoginProtocolFactory built-ins.
    return {'name': name, 'protocol': 'openid-connect',
            'protocolMapper': 'oidc-usersessionmodel-note-mapper', 'config': {
                'user.session.note': note or claim, 'claim.name': claim, 'jsonType.label': json_type,
                'access.token.claim': 'true', 'id.token.claim': 'true',
                'introspection.token.claim': 'true'}}


def service_mappers():
    return [session_mapper(name, claim) for name, claim in (
        ('Client ID', 'client_id'), ('Client Host', 'clientHost'),
        ('Client IP Address', 'clientAddress'))]


def check_basic_scope(api, scope):
    # Do not trust a shared scope solely by name: it must not emit permissions.
    root = '/client-scopes/' + scope['id']
    actual = api.realm('GET', root + '/protocol-mappers/models')
    expected = [session_mapper('auth_time', 'auth_time', 'long', note='AUTH_TIME'),
                {'name': 'sub', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-sub-mapper',
                 'config': {'access.token.claim': 'true', 'introspection.token.claim': 'true'}}]
    # Keycloak 26.0.8 may explicitly store the equivalent UserInfo default.
    # Accept this one variant only; all other config keys still compare exactly.
    expected.append(dict(expected[0], config=dict(expected[0]['config'],
                                                 **{'userinfo.token.claim': 'true'})))
    if len(actual) != 2 or any(not any(compatible(a, e) for e in expected) for a in actual) or len({a['name'] for a in actual}) != 2:
        raise Failure('Shared basic scope differs from Keycloak 26 defaults; preserved for review.')
    mappings = api.realm('GET', root + '/scope-mappings')
    if mappings.get('realmMappings') or mappings.get('clientMappings'):
        raise Failure('Shared basic scope contains role mappings; preserved for review.')


def check_account_mappings(api, assigned):
    # Retain only the known stock default-role tree. Never remove any assignment.
    # These defaults are excluded from tokens by the narrow scopes/mappers checked below.
    realm_roles = assigned.get('realmMappings', [])
    if realm_roles:
        realm = api.realm('GET')
        default = realm.get('defaultRole', {})
        root_name = 'default-roles-' + REALM
        identity = ('id', 'name', 'clientRole', 'containerId', 'composite')
        if (len(realm_roles) != 1 or not default.get('id') or not realm.get('id')
                or default.get('name') != root_name
                or default.get('clientRole') is not False
                or default.get('containerId') != realm['id']
                or default.get('composite') is not True
                or any(realm_roles[0].get(key) != default.get(key) for key in identity)):
            raise Failure('Unexpected service-account default-role identity; assignments preserved.')
        accounts = api.realm('GET', '/clients?clientId=account')
        if len(accounts) != 1 or accounts[0]['clientId'] != 'account' or not accounts[0].get('id'):
            raise Failure('Built-in account client is missing or ambiguous.')
        account_id = accounts[0]['id']
        # Exact stock Keycloak 26 graph, not merely an allowlist of reachable roles.
        # RealmManager.setupAccountManagement: manage-account -> manage-account-links.
        edges = {
            root_name: {'offline_access', 'uma_authorization', 'view-profile', 'manage-account'},
            'manage-account': {'manage-account-links'},
            'offline_access': set(), 'uma_authorization': set(),
            'view-profile': set(), 'manage-account-links': set(),
        }
        realm_names = {root_name, 'offline_access', 'uma_authorization'}
        pending = [default]
        visited_names, visited_ids = set(), set()
        while pending:
            role = pending.pop()
            name = role.get('name')
            is_client = name not in realm_names
            if (name not in edges or name in visited_names or not role.get('id')
                    or role['id'] in visited_ids
                    or role.get('clientRole') is not is_client
                    or role.get('containerId') != (account_id if is_client else realm['id'])
                    or role.get('composite') is not bool(edges[name])):
                raise Failure('Modified default-role identity or composition; assignments preserved.')
            visited_names.add(name)
            visited_ids.add(role['id'])
            # Read even leaves: unexpected children must not be hidden by a false flag.
            children = api.realm('GET', '/roles-by-id/' + role['id'] + '/composites')
            if len(children) != len(edges[name]) or {child.get('name') for child in children} != edges[name]:
                raise Failure('Missing or unexpected default-role composition; assignments preserved.')
            pending.extend(children)
        if visited_names != set(edges):
            raise Failure('Incomplete default-role tree; assignments preserved.')
    check_mappings({'clientMappings': assigned.get('clientMappings', {})}, 'Service-account assignments')


def inspect(api, entry, complete=False):
    """Read-only preflight for resources this script owns; never repair conflicts."""
    root = '/clients/' + entry['id']
    if not compatible(entry, settings()):
        raise Failure('Existing machine client settings conflict; no automatic reconciliation performed.')
    defaults = api.realm('GET', root + '/default-client-scopes')
    optional = api.realm('GET', root + '/optional-client-scopes')
    if [s['name'] for s in defaults] != ['basic'] or optional:
        raise Failure('Machine client scope associations conflict; expected only basic and no optional scopes.')
    check_basic_scope(api, defaults[0])
    actual = api.realm('GET', root + '/protocol-mappers/models')
    expected = {mapper['name']: mapper for mapper in mappers() + service_mappers()}
    # Only these built-ins may explicitly store the equivalent UserInfo default.
    service_variants = {m['name']: dict(m, config=dict(m['config'],
                        **{'userinfo.token.claim': 'true'})) for m in service_mappers()}
    seen = set()
    for mapper in actual:
        name = mapper['name']
        if (name in seen or name not in expected
                or not (compatible(mapper, expected[name])
                        or (name in service_variants and compatible(mapper, service_variants[name])))):
            raise Failure('Machine protocol mapper conflict; existing mappers were preserved.')
        seen.add(name)
    roles = api.realm('GET', root + '/roles')
    if any(r['name'] != ROLE or r.get('composite') for r in roles):
        raise Failure('Unexpected machine client roles or composite role; preserved without changes.')
    scope = api.realm('GET', root + '/scope-mappings')
    check_mappings(scope, 'Machine role scopes')
    account = api.realm('GET', root + '/service-account-user')
    if api.realm('GET', '/users/' + account['id'] + '/groups'):
        raise Failure('Unexpected machine service-account group membership; preserved.')
    assigned = api.realm('GET', '/users/' + account['id'] + '/role-mappings')
    check_account_mappings(api, assigned)
    if roles:
        for kind in ('users', 'groups'):
            offset = 0
            while True:
                members = api.realm('GET', root + '/roles/' + ROLE + '/' + kind
                                    + '?first=' + str(offset) + '&max=100')
                if any(kind == 'groups' or member['id'] != account['id'] for member in members):
                    raise Failure('Machine role assigned to another user or group; assignments preserved.')
                if len(members) < 100:
                    break
                offset += len(members)
    if complete and (not {m['name'] for m in mappers()}.issubset(seen) or not roles or not has_role(scope) or not has_role(assigned)):
        raise Failure('Machine provisioning is incomplete.')
    return root, account, seen, roles


def check_mappings(value, label):
    if value.get('realmMappings'):
        raise Failure(label + ' contain realm roles; preserved. Explicit operator review is required.')
    for name, mapping in value.get('clientMappings', {}).items():
        if name != CLIENT or any(r['name'] != ROLE or r.get('composite') for r in mapping['mappings']):
            raise Failure(label + ' contain unexpected client roles; preserved. Explicit operator review is required.')


def has_role(value):
    return any(r['name'] == ROLE for r in value.get('clientMappings', {}).get(CLIENT, {}).get('mappings', []))


def provision(api, resume_disabled=False):
    entry = client(api)
    created = entry is None
    if created:
        scopes = api.realm('GET', '/client-scopes')
        if len([s for s in scopes if s['name'] == 'basic']) != 1:
            raise Failure('Expected basic client scope is missing or ambiguous; realm unchanged.')
        check_basic_scope(api, next(s for s in scopes if s['name'] == 'basic'))
        api.realm('POST', '/clients', dict(settings(), enabled=False,
                  defaultClientScopes=['basic'], optionalClientScopes=[]))
        entry = client(api)
        if entry is None:
            raise Failure('Machine client creation could not be confirmed.')
    if not created and not entry.get('enabled') and not resume_disabled:
        raise Failure('Existing client is disabled; no writes performed. Review then use --resume-disabled.')
    # Enabled clients must already be complete; never repair a live partial configuration.
    root, account, seen, roles = inspect(api, entry, complete=bool(entry.get('enabled')))
    if entry.get('enabled'):
        print('PASS: existing machine configuration is complete; no writes needed.')
        return
    for mapper in mappers():
        if mapper['name'] not in seen:
            api.realm('POST', root + '/protocol-mappers/models', mapper)
    if not roles:
        api.realm('POST', root + '/roles', {'name': ROLE, 'composite': False})
    role = api.realm('GET', root + '/roles/' + ROLE)
    api.realm('POST', root + '/scope-mappings/clients/' + entry['id'], [role])
    api.realm('POST', '/users/' + account['id'] + '/role-mappings/clients/' + entry['id'], [role])
    inspect(api, api.realm('GET', root), complete=True)
    api.realm('PUT', root, {'enabled': True, 'serviceAccountsEnabled': True})
    print('PASS: machine configuration provisioned; existing identifiers and credentials preserved.')


def repair_assignments_match(actual, expected, client_id, role_id):
    """Normalize only empty attributes on the single newly assigned machine role.

    Keycloak's brief role representation omits attributes; the full representation
    includes them. No other assignment fields or existing roles are normalized.
    """
    def normalized(value):
        result = copy.deepcopy(value)
        mapping = result.get('clientMappings', {}).get(CLIENT, {})
        roles = mapping.get('mappings', [])
        if (mapping.get('id') != client_id or mapping.get('client') != CLIENT
                or len(roles) != 1):
            return None
        role = roles[0]
        if (not role_id or role.get('id') != role_id or role.get('name') != ROLE
                or role.get('containerId') != client_id
                or role.get('clientRole') is not True or role.get('composite') is not False):
            return None
        if role.get('attributes') == {}:
            del role['attributes']
        return result

    left, right = normalized(actual), normalized(expected)
    return left is not None and right is not None and left == right


def repair_missing_role(api):
    """Explicit, single-purpose repair; no resource creation or credential changes."""
    stage = 'initial preflight'
    try:
        entry = client(api)
        if entry is None or type(entry.get('enabled')) is not bool:
            raise Failure('Invalid client state.')
        root = '/clients/' + entry['id']
    except (Exception, KeyboardInterrupt):
        raise Failure('Repair failed at initial preflight; no writes performed; client state unconfirmed.') from None

    def state():
        current = api.realm('GET', root)
        _, account, seen, roles = inspect(api, current)
        scope = api.realm('GET', root + '/scope-mappings')
        assigned = api.realm('GET', '/users/' + account['id'] + '/role-mappings')
        if (current.get('id') != entry['id']
                or not {m['name'] for m in mappers()}.issubset(seen)
                or len(roles) != 1 or roles[0]['name'] != ROLE or not has_role(scope)):
            raise Failure('Repair prerequisites changed; refusing assignment.')
        # Compare preserved resources across the disable boundary and final validation.
        snapshot = {
            'client': {k: v for k, v in current.items() if k != 'enabled'},
            'account_id': account['id'], 'roles': roles, 'scope': scope,
            'assigned': assigned,
            'mappers': sorted(api.realm('GET', root + '/protocol-mappers/models'), key=lambda m: m['name']),
            'default_scopes': api.realm('GET', root + '/default-client-scopes'),
            'optional_scopes': api.realm('GET', root + '/optional-client-scopes'),
        }
        return current, account, roles[0], snapshot

    started = False
    assignment_path = None
    expected_assigned = None
    try:
        current, account, role, before = state()
        if has_role(before['assigned']):
            raise Failure('Direct assignment must be missing.')
        expected_assigned = copy.deepcopy(before['assigned'])
        expected_clients = expected_assigned.setdefault('clientMappings', {})
        expected_mapping = expected_clients.setdefault(CLIENT, {
            'id': entry['id'], 'client': CLIENT, 'mappings': []})
        if (expected_mapping.get('id') != entry['id']
                or expected_mapping.get('client') != CLIENT):
            raise Failure('Unexpected mapping identity.')
        expected_mapping['mappings'].append(copy.deepcopy(before['roles'][0]))
        assignment_path = '/users/' + account['id'] + '/role-mappings'

        stage = 'client disable and confirmation'
        started = True
        if current.get('enabled') is True:
            api.realm('PUT', root, {'enabled': False, 'serviceAccountsEnabled': True})
        if api.realm('GET', root).get('enabled') is not False:
            raise Failure('Disable not confirmed.')

        stage = 'pre-assignment configuration comparison'
        current, account, role, disabled = state()
        if current.get('enabled') is not False or disabled != before:
            raise Failure('Configuration changed.')

        stage = 'direct role-assignment request'
        api.realm('POST', assignment_path + '/clients/' + entry['id'], [role])
        stage = 'assignment persistence verification'
        if not repair_assignments_match(api.realm('GET', assignment_path), expected_assigned,
                                        entry['id'], before['roles'][0]['id']):
            raise Failure('Exact assignment not persisted.')

        stage = 'complete configuration validation'
        current = api.realm('GET', root)
        inspect(api, current, complete=True)

        stage = 'final configuration comparison'
        current, account, role, after = state()
        if (current.get('enabled') is not False
                or {k: v for k, v in after.items() if k != 'assigned'} !=
                   {k: v for k, v in before.items() if k != 'assigned'}
                or not repair_assignments_match(after['assigned'], expected_assigned,
                                                entry['id'], before['roles'][0]['id'])):
            raise Failure('Unexpected configuration change.')

        stage = 'client re-enable and confirmation'
        api.realm('PUT', root, {'enabled': True, 'serviceAccountsEnabled': True})
        current = api.realm('GET', root)
        if current.get('enabled') is not True:
            raise Failure('Re-enable not confirmed.')
        # Keycloak 26 updates can affect the service-account user. Validate after
        # the final PUT, not only before it, against the original identity/state.
        _, enabled_account, _, _ = inspect(api, current, complete=True)
        if enabled_account['id'] != before['account_id']:
            raise Failure('Service-account identity changed during re-enable.')
        current, _, _, enabled_state = state()
        if (current.get('enabled') is not True
                or {k: v for k, v in enabled_state.items() if k != 'assigned'} !=
                   {k: v for k, v in before.items() if k != 'assigned'}
                or not repair_assignments_match(enabled_state['assigned'], expected_assigned,
                                                entry['id'], before['roles'][0]['id'])):
            raise Failure('Configuration changed during re-enable.')
    except (Exception, KeyboardInterrupt):
        assignment_status = ''
        if stage == 'direct role-assignment request':
            # A failed response does not imply rollback. Read once, never retry POST.
            try:
                persisted = api.realm('GET', assignment_path)
                status = ('exact assignment confirmed' if repair_assignments_match(
                    persisted, expected_assigned, entry['id'], before['roles'][0]['id'])
                          else 'assignment unchanged' if persisted == before['assigned']
                          else 'assignment differs from expected')
            except (Exception, KeyboardInterrupt):
                status = 'assignment state unconfirmed'
            assignment_status = ' ' + status + '; assignment request was not retried.'
        try:
            # Do not mutate unsafe preflight configurations. Confirm state read-only.
            if started:
                api.realm('PUT', root, {'enabled': False, 'serviceAccountsEnabled': True})
            disabled = api.realm('GET', root).get('enabled') is False
            outcome = ('machine client is confirmed disabled' if disabled else
                       'client is enabled; preflight made no writes')
        except (Exception, KeyboardInterrupt):
            outcome = 'disabled state could not be confirmed; operator intervention required'
        raise Failure('Repair failed at ' + stage + '; ' + outcome + '.'
                      + assignment_status + ' Assignments were not rolled back.') from None
    print('PASS: missing direct policy.read assignment repaired and validated; client re-enabled.')


def run(main):
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        message = str(error) if isinstance(error, Failure) else 'Operation failed; sensitive details suppressed.'
        print('ERROR: ' + message, file=sys.stderr)
        return 1
    return 0


def main():
    args = arguments('Provision the dedicated machine client (writes to Keycloak).', provisioning=True)
    api = connect(args)
    if args.repair_missing_role:
        repair_missing_role(api)
    else:
        provision(api, resume_disabled=args.resume_disabled)


if __name__ == '__main__':
    sys.exit(run(main))
