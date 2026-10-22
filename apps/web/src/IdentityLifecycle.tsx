import type { User } from 'oidc-client-ts';

export function CurrentIdentity({ user, principal, tenants, loading }: {
  user: User | null; principal: string; tenants: string[]; loading: boolean;
}) {
  return <section className="panel"><div className="panel-heading"><div><h2>Current Identity</h2><p>Your authenticated session · not an organization-wide directory</p></div><span className="demo-badge">LIVE API</span></div>
    {loading ? <p role="status" className="p-6 text-sm text-slate-500">Loading current identity…</p> : !user ? <p role="status" className="p-6 text-sm text-slate-500">Sign in with Keycloak to view your identity.</p> : <div className="p-6">
      <div className="flex items-center gap-4 mb-6"><span aria-hidden="true" className="component-mark">◎</span><div><h3 className="font-semibold">{user.profile.name ?? user.profile.preferred_username ?? 'Signed-in identity'}</h3><p className="mt-1 text-xs text-slate-500">Display label from OIDC session; permissions are determined by the API.</p></div></div>
      <dl className="grid gap-6 sm:grid-cols-2 text-sm">{Object.entries({
        'Authentication provider': 'Keycloak · OpenID Connect',
        'Authentication state': 'Signed in',
        'Internal principal ID': principal || 'Unavailable — identity API lookup did not succeed',
        'Tenant context': principal ? (tenants.length ? tenants.join(', ') : 'No active tenant memberships returned') : 'Unavailable',
      }).map(([label,value]) => <div key={label}><dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt><dd className="mt-2 break-words font-medium">{value}</dd></div>)}</dl>
      <p className="mt-6 border-t border-slate-100 pt-4 text-xs text-slate-500">Principal and tenant context come only from /api/v1/me. No roles are inferred or displayed. This is a session snapshot, not a new access decision.</p>
    </div>}
  </section>;
}
const scenarios = [
  { title: 'Joiner', subtitle: 'Stage identity without granting access', steps: [
    ['Identity staging', 'PENDING_PROVISIONING → AWAITING_OPENFGA_VERIFICATION'],
    ['Eligibility remains disabled', 'New principal and membership remain DISABLED.'],
    ['Activation requirements', 'Trusted authority, verified relationships and guarded activation are still required.'],
  ], source: 'JoinerServiceTest.newJoinerIsDurableButNeverEligible', limit: 'Internal staging integration test. No privileged activation is implemented.' },
  { title: 'Mover', subtitle: 'Revoke before granting destination access', steps: [
    ['Before', 'ACME project and inherited document can be read in the fixture.'],
    ['Access revoked', 'Neither ACME nor GLOBEX is readable in the gap snapshot.'],
    ['After', 'GLOBEX can be read; ACME remains denied. Edit/delete remain denied.'],
  ], source: 'OpenFGA: portfolio-mover-before / revoked-gap / after', limit: 'Three independent relationship snapshots, not a live transfer. Destination viewer grants are explicit test fixtures.' },
  { title: 'Leaver', subtitle: 'Tenant eligibility takes precedence', steps: [
    ['Membership disable', 'Test SQL changes only the selected tenant membership to DISABLED.'],
    ['Subsequent access denied', 'The same test identity receives a resource-service 404, even with mocked OpenFGA ALLOW.'],
    ['Unrelated access preserved', 'Other tenant membership and global principal remain ACTIVE.'],
  ], source: 'LeaverEligibilityTest.activeAllowsThenSameAuthenticatedIdentityLosesAccessDespiteFgaAllow', limit: 'Real PostgreSQL with synthetic JWT and mocked authorization dependencies. No administrative offboarding command exists.' },
];
export function LifecycleOverview() {
  return <><section className="panel p-6"><span className="demo-badge">Automated Test Demonstration</span><h2 className="mt-4 text-xl">Identity lifecycle, explained</h2><p className="mt-2 text-sm leading-6 text-slate-500">Read-only summaries of documented test scenarios. These are not live workflow executions, current job statuses or authorization decisions. Nothing is provisioned or changed from this screen.</p></section>
    <div className="grid gap-5 xl:grid-cols-3">{scenarios.map(s => <section className="panel p-6" key={s.title}><span className="eyebrow text-blue-600">Automated Test Demonstration</span><h2 className="mt-3 text-xl">{s.title}</h2><p className="mt-2 text-sm text-slate-500">{s.subtitle}</p><ol className="mt-6 grid gap-5">{s.steps.map(([title,desc],i) => <li key={title} className="flex gap-3"><span className="text-xs text-blue-600 font-semibold pt-1">0{i+1}</span><div><h3 className="text-sm font-semibold">{title}</h3><p className="mt-1 text-xs leading-6 text-slate-500">{desc}</p></div></li>)}</ol><div className="mt-6 border-t border-slate-100 pt-4"><p className="text-xs leading-5 text-slate-500">{s.limit}</p><p className="mt-3 text-[11px] font-mono break-words text-slate-500">Source: {s.source}</p></div></section>)}</div>
    <section className="panel p-6"><h2>Reproduce the evidence</h2><p className="mt-2 text-sm text-slate-500">Follow docs/demo/phase4-portfolio-demo.md in the repository. Run the existing isolated tests; this screen does not execute or report their latest results.</p></section></>;
}
