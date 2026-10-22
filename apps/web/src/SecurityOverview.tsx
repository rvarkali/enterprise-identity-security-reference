const examples = [
  ['Authorization success', 'ALLOW', 'ALL_GATES_PASSED'],
  ['Eligibility denial', 'DENY', 'RESOURCE_OR_ELIGIBILITY'],
  ['Relationship denial scenario', 'DENY', 'RELATIONSHIP_OR_ELIGIBILITY_DENY'],
  ['OPA denial', 'DENY', 'OPA_DENY'],
  ['Dependency failure', 'ERROR', 'DEPENDENCY_OR_INTERNAL_FAILURE'],
];
export function SampleEvents() {
  return <section className="panel"><div className="panel-heading"><div><h2>Sample Events — Demo Data</h2><p>Static examples of RESOURCE_AUTHORIZATION events · not live application logs</p></div><span className="demo-badge">SYNTHETIC EXAMPLES</span></div>
    <div className="overflow-x-auto"><table><thead><tr>{['Example / UTC time', 'Principal reference', 'Outcome', 'Generic reason'].map(h => <th key={h} scope="col">{h}</th>)}</tr></thead><tbody>{examples.map(([title,outcome,reason],i) => <tr key={reason}><td><div className="font-semibold text-slate-800">{title}</div><div className="mt-1 text-xs">2026-01-15 09:4{i}:00Z</div></td><td className="font-mono text-xs">d0000000-0000-4000-8000-000000000001</td><td><span className={`status ${outcome === 'ALLOW' ? 'allowed' : outcome === 'ERROR' ? 'staged' : 'denied'}`}>{outcome}</span></td><td className="font-mono text-xs">{reason}</td></tr>)}</tbody></table></div>
    <div className="p-6 border-t border-slate-100 grid gap-4"><p className="text-xs leading-6 text-slate-500">All identifiers and timestamps are synthetic. Action: can_view · Resource type: document. Tenant and resource references are omitted on every denial/error. A relationship-denial category can also represent eligibility denial; it does not prove an OpenFGA-specific cause.</p>
      <details className="text-sm"><summary className="cursor-pointer text-blue-700 font-medium">Example fields & redaction</summary><pre className="mt-3 overflow-x-auto rounded-lg bg-slate-50 p-4 text-xs leading-6">{`event_type=RESOURCE_AUTHORIZATION\ntimestamp=2026-01-15T09:41:00Z\ncorrelation_id=e0000000-0000-4000-8000-000000000002\nprincipal_id=d0000000-0000-4000-8000-000000000001\ntenant_id=null\nresource_type=document\nresource_id=null\naction=can_view\noutcome=DENY\nreason=RESOURCE_OR_ELIGIBILITY`}</pre><p className="mt-3 text-xs text-slate-500">No names, email, JWTs, secrets, classifications, resource content or exception details. Application logs are not a durable audit ledger. No event-query API exists.</p></details>
    </div></section>;
}
const integrations = [
  ['KC', 'Keycloak', 'Authentication integrated', 'OIDC Authorization Code + PKCE. Identity authentication remains separate from access decisions.', true],
  ['PG', 'PostgreSQL', 'Identity & tenant storage', 'Authoritative internal principals, memberships and resource ownership.', true],
  ['FG', 'OpenFGA', 'Relationship authorization', 'Tenant membership and project/document permission checks.', true],
  ['OP', 'OPA', 'Attribute authorization', 'Additional contextual policy gate. Confidential access stays denied without trusted assurance.', true],
  ['EN', 'Microsoft Entra ID', 'Federation planned', 'Future enterprise federation. No Entra connection or synchronization is implemented.', false],
] as const;
export function IntegrationOverview() {
  return <section className="panel"><div className="panel-heading"><div><h2>Platform integrations</h2><p>Implementation inventory · service health is not checked</p></div><span className="demo-badge">ARCHITECTURE</span></div>
    <div className="grid gap-4 p-6 md:grid-cols-2">{integrations.map(([mark,name,title,description,implemented]) => <article className="rounded-lg border border-slate-200 p-5" key={name}><div className="flex flex-wrap items-center gap-3"><span className="component-mark">{mark}</span><h3 className="font-semibold">{name}</h3><span className={`status ${implemented ? 'allowed' : 'staged'}`}>{implemented ? 'Implemented' : 'Planned · not integrated'}</span></div><p className="mt-4 text-sm font-medium">{title}</p><p className="mt-2 text-xs leading-6 text-slate-500">{description}</p><p className="mt-4 text-xs text-slate-500">{implemented ? 'Current health: not verified' : 'No live connection'}</p></article>)}</div></section>;
}
