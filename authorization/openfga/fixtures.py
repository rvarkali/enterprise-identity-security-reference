"""Trusted local demo provisioning and read-only reconciliation. No arbitrary ownership input."""
import argparse
import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

from deploy import Api, ROOT, STORE_NAME, canonical, identifier, require

ALICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PROJECTS = [
    ("ac100000-0000-4000-8000-000000000001", "acme", "ACME shared project", ALICE),
    ("ac100000-0000-4000-8000-000000000002", "acme", "ACME private project", None),
    ("b0100000-0000-4000-8000-000000000001", "globex", "GLOBEX shared project", BOB),
]
DOCUMENTS = [
    ("ac200000-0000-4000-8000-000000000001", "acme", PROJECTS[0][0], "ACME shared document"),
    ("b0200000-0000-4000-8000-000000000001", "globex", PROJECTS[2][0], "GLOBEX shared document"),
]


def command(args, text=None):
    result = subprocess.run(args, cwd=ROOT, input=text, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, f"Command failed: {args[0]} (check local service availability/configuration)")
    return result.stdout


def sql(statement):
    return command(["docker", "compose", "exec", "-T", "postgres", "sh", "-c",
                    'exec psql -U "$POSTGRES_USER" -d iam -X -qAt -v ON_ERROR_STOP=1'], statement)


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def snapshot():
    project_ids = ",".join(literal(p[0]) for p in PROJECTS)
    document_ids = ",".join(literal(d[0]) for d in DOCUMENTS)
    result = json.loads(sql(f"""
      BEGIN READ ONLY;
      SELECT json_build_object(
        'tenants', (SELECT coalesce(json_agg(x), '[]') FROM
          (SELECT id, slug, status FROM tenants WHERE slug IN ('acme','globex') ORDER BY slug) x),
        'memberships', (SELECT coalesce(json_agg(x), '[]') FROM
          (SELECT tp.principal_id, t.slug, tp.status, p.status AS principal_status, t.status AS tenant_status
           FROM tenant_principals tp JOIN tenants t ON t.id=tp.tenant_id
           JOIN principals p ON p.id=tp.principal_id WHERE t.slug IN ('acme','globex')
           ORDER BY t.slug, tp.principal_id) x),
        'projects', (SELECT coalesce(json_agg(x), '[]') FROM
          (SELECT id, tenant_id, name FROM projects WHERE id IN ({project_ids}) ORDER BY id) x),
        'documents', (SELECT coalesce(json_agg(x), '[]') FROM
          (SELECT id, tenant_id, project_id, name, classification FROM documents
           WHERE id IN ({document_ids}) ORDER BY id) x));
      COMMIT;
    """))
    require(isinstance(result, dict) and all(isinstance(result.get(k), list)
            for k in ('tenants', 'memberships', 'projects', 'documents')), "Invalid PostgreSQL snapshot")
    return result


def seed():
    # The complete fixed seed is transactional. Existing rows are never updated.
    inserts = []
    guards = []
    for pid, slug, name, _ in PROJECTS:
        inserts.append(f"INSERT INTO projects(id,tenant_id,name) SELECT {literal(pid)}::uuid,id,{literal(name)} "
                       f"FROM tenants WHERE slug={literal(slug)} ON CONFLICT (id) DO NOTHING;")
        guards.append(f"EXISTS(SELECT 1 FROM projects p JOIN tenants t ON t.id=p.tenant_id "
                      f"WHERE p.id={literal(pid)}::uuid AND t.slug={literal(slug)})")
    for did, slug, parent, name in DOCUMENTS:
        inserts.append(f"INSERT INTO documents(id,tenant_id,project_id,name,classification) "
                       f"SELECT {literal(did)}::uuid,id,{literal(parent)}::uuid,{literal(name)},'INTERNAL' "
                       f"FROM tenants WHERE slug={literal(slug)} ON CONFLICT (id) DO NOTHING;")
        guards.append(f"EXISTS(SELECT 1 FROM documents d JOIN tenants t ON t.id=d.tenant_id "
                      f"WHERE d.id={literal(did)}::uuid AND t.slug={literal(slug)} "
                      f"AND d.project_id={literal(parent)}::uuid)")
    for user, slug in [(ALICE, 'acme'), (BOB, 'globex')]:
        guards.append(f"EXISTS(SELECT 1 FROM tenant_principals tp JOIN tenants t ON t.id=tp.tenant_id "
                      f"JOIN principals p ON p.id=tp.principal_id WHERE p.id={literal(user)}::uuid "
                      f"AND t.slug={literal(slug)} AND p.status='ACTIVE' AND t.status='ACTIVE' AND tp.status='ACTIVE')")
    sql("BEGIN; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='15s';\n" +
        "\n".join(inserts) + "\nDO $$ BEGIN IF NOT (" + " AND ".join(guards) +
        ") THEN RAISE EXCEPTION 'Fixture ownership or ACTIVE membership conflict'; END IF; END $$; COMMIT;")


def configured_api():
    # Compose resolves .env and exported overrides exactly as it does for the API container.
    config = json.loads(command(["docker", "compose", "config", "--format", "json"]))
    env = config["services"]["api"]["environment"]
    store = identifier(env.get("OPENFGA_STORE_ID"))
    model = identifier(env.get("OPENFGA_AUTHORIZATION_MODEL_ID"))
    api = Api(os.environ.get("OPENFGA_DEPLOY_API_URL", "http://localhost:8082"))
    require(api.request(f"/stores/{store}").get("name") == STORE_NAME, "Configured store is not the dedicated demo store")
    deployed = api.request(f"/stores/{store}/authorization-models/{model}").get("authorization_model")
    local = json.loads(command(["docker", "run", "--rm", "--network", "none", "--mount",
        f"type=bind,source={ROOT / 'authorization/openfga'},target=/model,readonly", "--workdir", "/model",
        "openfga/cli:v0.8.2", "model", "transform", "--file", "model.fga", "--output-format", "json"]))
    require(canonical(deployed) == canonical(local), "Configured model does not match model.fga")
    return api, store, model


def read_tuples(api, store):
    objects = ['tenant:acme', 'tenant:globex'] + ['project:' + p[0] for p in PROJECTS] + ['document:' + d[0] for d in DOCUMENTS]
    tuples = []
    for obj in objects:
        token = ""
        seen = set()
        while True:
            page = api.request(f"/stores/{store}/read", {
                "tuple_key": {"object": obj}, "page_size": 100, "continuation_token": token,
                "consistency": "HIGHER_CONSISTENCY"})
            require(isinstance(page.get('tuples'), list), "Invalid tuple read response")
            for row in page['tuples']:
                key = row.get('key') if isinstance(row, dict) else None
                require(isinstance(key, dict) and key.get('object') == obj and
                        all(isinstance(key.get(k), str) for k in ('user', 'relation')), "Invalid tuple key")
                tuples.append(key)
            token = page.get('continuation_token', '')
            require(isinstance(token, str) and token not in seen, "Invalid tuple pagination")
            if not token:
                break
            seen.add(token)
    return sorted(tuples, key=lambda t: json.dumps(t, sort_keys=True))


def key_tuple(key):
    return key['user'], key['relation'], key['object']


def reconcile(db, tuples):
    """Return desired tuples, missing items and conflicts. Never performs I/O."""
    missing, conflicts = [], []
    tenants = {t['slug']: t for t in db['tenants']}
    active = {(m['principal_id'], m['slug']) for m in db['memberships']
              if m['status'] == m['principal_status'] == m['tenant_status'] == 'ACTIVE'}
    for user, slug in [(ALICE, 'acme'), (BOB, 'globex')]:
        if slug not in tenants or tenants[slug]['status'] != 'ACTIVE' or (user, slug) not in active:
            conflicts.append(f"Required ACTIVE PostgreSQL membership missing: {user} in {slug}")
    desired = {(f'user:{ALICE}', 'member', 'tenant:acme'), (f'user:{BOB}', 'member', 'tenant:globex')}
    ownership = {}
    for kind, fixtures, rows in [('project', PROJECTS, db['projects']), ('document', DOCUMENTS, db['documents'])]:
        indexed = {row['id']: row for row in rows}
        for fixture in fixtures:
            rid, slug = fixture[:2]
            row = indexed.get(rid)
            obj = f'{kind}:{rid}'
            relation = 'tenant' if kind == 'project' else 'parent'
            owner = 'tenant:' + slug if kind == 'project' else 'project:' + fixture[2]
            if row is None:
                missing.append('PostgreSQL ' + obj)
            elif row['tenant_id'] != tenants.get(slug, {}).get('id') or (
                    kind == 'document' and row['project_id'] != fixture[2]):
                conflicts.append('PostgreSQL ownership conflict: ' + obj)
            # Fixed fixture plan is permitted only if existing PostgreSQL ownership agrees.
            # After seeding, this is re-evaluated against the authoritative rows before tuple writes.
            ownership[(obj, relation)] = owner
            desired.add((owner, relation, obj))
            if kind == 'project' and fixture[3]:
                desired.add(('user:' + fixture[3], 'viewer', obj))
    actual = {key_tuple(t) for t in tuples}
    for (obj, relation), expected in ownership.items():
        links = [t for t in tuples if t['object'] == obj and t['relation'] == relation]
        if len(links) > 1:
            conflicts.append('Multiple ownership relationships: ' + obj)
        if any(t['user'] != expected or t.get('condition') for t in links):
            conflicts.append('Incorrect ownership relationship: ' + obj)
    for t in tuples:
        user, relation, obj = key_tuple(t)
        if obj.startswith('tenant:') and relation in ('member', 'admin'):
            if not user.startswith('user:') or (user[5:], obj[7:]) not in active or t.get('condition'):
                conflicts.append(f'Stale/unsupported membership tuple: {user} {relation} {obj}')
            if user in ('user:' + ALICE, 'user:' + BOB) and (user, relation, obj) not in desired:
                conflicts.append(f'Unexpected demo tenant grant: {user} {relation} {obj}')
        elif obj.startswith(('project:', 'document:')) and (obj, relation) not in ownership:
            if (user, relation, obj) not in desired or t.get('condition'):
                conflicts.append(f'Unexpected resource grant: {user} {relation} {obj}')
    for item in sorted(desired - actual):
        missing.append('OpenFGA ' + ' '.join(item))
    return desired, missing, conflicts


def checks(api, store, model):
    results = []
    for user in (ALICE, BOB):
        for kind, fixtures in [('project', PROJECTS), ('document', DOCUMENTS)]:
            for fixture in fixtures:
                expected = (user == ALICE and fixture[1] == 'acme' or user == BOB and fixture[1] == 'globex')
                if kind == 'project' and fixture[3] is None:
                    expected = False
                obj = f'{kind}:{fixture[0]}'
                result = api.request(f'/stores/{store}/check', {
                    'authorization_model_id': model, 'consistency': 'HIGHER_CONSISTENCY',
                    'tuple_key': {'user': 'user:' + user, 'relation': 'can_view', 'object': obj}})
                require(type(result.get('allowed')) is bool, 'Invalid Check response')
                require(result['allowed'] == expected, f'Authorization mismatch: {user} can_view {obj}')
                results.append(f"{'Alice' if user == ALICE else 'Bob'} can_view {obj}: {result['allowed']}")
    print('\n'.join(results))
    print('PASS: 10 authorization checks')


def run(mode, api, store, model):
    before_db, before_tuples = snapshot(), read_tuples(api, store)
    desired, missing, conflicts = reconcile(before_db, before_tuples)
    for problem in conflicts + missing:
        print(('CONFLICT: ' if problem in conflicts else 'MISSING: ') + problem)
    if mode == 'audit':
        require(before_db == snapshot() and before_tuples == read_tuples(api, store),
                'State changed during audit (possible external writer); no audit writes were issued')
        require(not conflicts and not missing, 'Audit found inconsistencies; no changes made')
        checks(api, store, model)
        print('PASS: read-only audit; before/after PostgreSQL and relevant tuples unchanged')
        return
    require(not conflicts, 'Provisioning blocked by conflicts; no writes issued')
    seed()
    db, tuples = snapshot(), read_tuples(api, store)
    desired, missing, conflicts = reconcile(db, tuples)
    require(not conflicts and not any(m.startswith('PostgreSQL') for m in missing),
            'Post-seed ownership/membership inconsistency; no OpenFGA writes issued')
    additions = desired - {key_tuple(t) for t in tuples}
    if additions:
        result = api.request(f'/stores/{store}/write', {'authorization_model_id': model,
            'writes': {'tuple_keys': [dict(zip(('user', 'relation', 'object'), item)) for item in sorted(additions)]}})
        require(result == {}, 'Invalid tuple write response; rerun audit before proceeding')
    _, missing, conflicts = reconcile(snapshot(), read_tuples(api, store))
    require(not missing and not conflicts, 'Post-provision reconciliation failed; inspect audit (nothing deleted)')
    checks(api, store, model)
    print(f'PASS: fixtures reconciled; {len(additions)} tuples added, {len(desired) - len(additions)} reused')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['provision', 'audit'])
    args = parser.parse_args()
    with open(__file__) as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another fixture operation is running from this checkout') from None
        api, store, model = configured_api()
        run(args.mode, api, store, model)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
