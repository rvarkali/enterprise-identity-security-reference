import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { User } from 'oidc-client-ts';
import { auth } from './auth';
import './style.css';
import { apiRead } from './api';
import { AccessExplorer } from './AccessExplorer';
import { CurrentIdentity, LifecycleOverview } from './IdentityLifecycle';
import { SampleEvents, IntegrationOverview } from './SecurityOverview';

const sections = ['Dashboard', 'Identities', 'Access Explorer', 'Lifecycle', 'Security Events', 'Integrations'] as const;
type Section = typeof sections[number];
const icons = ['◫', '◎', '⌘', '⇄', '▤', '◇'];
function Badge({ children }: { children: React.ReactNode }) { return <span className="demo-badge">{children}</span>; }
function Dashboard({ navigate }: { navigate: (section: Section) => void }) { return <>
  <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{[['Total identities', '248', 'Human & workload identities', '◎'], ['Active tenants', '2', 'ACME and GLOBEX', '◇'], ['Authorization decisions', '1,842', 'Illustrative 24-hour total', '⌘'], ['Lifecycle workflows', '12', 'Illustrative staged workflows', '⇄']].map(([label, value, detail, icon]) => <section className="metric" key={label}><div className="flex justify-between items-center"><span className="text-sm font-medium text-slate-600">{label}</span><span className="text-blue-600 text-xl" aria-hidden="true">{icon}</span></div><div className="mt-5 flex items-end gap-3"><strong className="text-4xl tracking-tight font-semibold">{value}</strong><span className="mb-1 text-[10px] tracking-wider text-slate-500">DEMO</span></div><p className="mt-3 text-xs text-slate-500">{detail}</p></section>)}</div>
  <div className="grid gap-5 xl:grid-cols-[1.8fr_1fr]"><section className="panel p-6"><div className="flex justify-between gap-3"><div><h2>Every request. Every boundary.</h2><p className="mt-2 text-sm text-slate-500">A layered approach to resource authorization.</p></div><span className="text-blue-600 text-2xl" aria-hidden="true">⌘</span></div><div className="mt-7 grid grid-cols-2 gap-3 sm:grid-cols-4">{['Verify identity', 'Check tenant', 'Evaluate access', 'Apply context'].map((label, i) => <div key={label} className="gate"><span>0{i + 1}</span><p>{label}</p></div>)}</div><button className="text-link mt-5" onClick={() => navigate('Access Explorer')}>Explore the authorization model <span aria-hidden="true">→</span></button></section><section className="posture"><span className="eyebrow text-blue-200">PORTFOLIO REFERENCE</span><h2 className="mt-3 text-xl text-white">Trust is evaluated,<br />never assumed.</h2><p className="mt-3 text-sm leading-6 text-slate-300">Tenant isolation, relationship checks and contextual policy work together.</p><div className="mt-5 border-t border-white/15 pt-4 text-xs text-blue-200">Read-only console · No privileged controls</div></section></div>
  <div className="flex flex-wrap gap-3">{(['Identities', 'Lifecycle', 'Security Events', 'Integrations'] as const).map(item => <button key={item} className="session-button" onClick={() => navigate(item)}>View {item} <span aria-hidden="true">→</span></button>)}</div>
  <SampleEvents /><IntegrationOverview />
</>; }
function SectionContent({ section }: { section: Section }) {
  if (section === 'Security Events') return <SampleEvents />;
  if (section === 'Integrations') return <IntegrationOverview />;
  return null;
}
function App() {
  const [section, setSection] = useState<Section>('Dashboard');
  const [collapsed, setCollapsed] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [principal, setPrincipal] = useState('');
  const [tenants, setTenants] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        if (window.location.pathname === '/auth/callback') { await auth.signinRedirectCallback(); window.history.replaceState({}, '', '/'); }
        const current = await auth.getUser();
        if (!active || !current || current.expired) return;
        setUser(current);
        const profile = await apiRead('/api/v1/me', current) as { principalId: string; tenants: { display_name: string }[] };
        if (typeof profile.principalId !== 'string' || !Array.isArray(profile.tenants) || !profile.tenants.every(t => typeof t.display_name === 'string')) throw new Error();
        if (active) { setPrincipal(profile.principalId); setTenants(profile.tenants.map(t => t.display_name)); }
      } catch { if (active) setError('Live session details are unavailable. Check that the API and Keycloak are running.'); }
      finally { if (active) setLoading(false); }
    };
    void load();
    const expired = () => { active = false; setLoading(false); setUser(null); setTenants([]); setPrincipal(''); };
    auth.events.addAccessTokenExpired(expired);
    return () => { active = false; auth.events.removeAccessTokenExpired(expired); };
  }, []);
  const login = async () => { try { await auth.signinRedirect(); } catch { setError('Unable to start Keycloak sign-in.'); } };
  const logout = async () => { try { await auth.signoutRedirect(); } catch { setError('Unable to complete Keycloak sign-out.'); } };
  return <div className={collapsed ? 'shell collapsed' : 'shell'}><a href="#content" className="skip-link">Skip to content</a><aside className="sidebar"><div className="brand"><span className="brand-mark">IG</span><div className="nav-label"><strong>IdentityGuard</strong><small>SECURITY CONSOLE</small></div></div><div className="nav-label sidebar-caption">WORKSPACE</div><nav aria-label="Main navigation">{sections.map((item, i) => <button title={item} key={item} aria-current={section === item ? 'page' : undefined} onClick={() => setSection(item)} className={section === item ? 'nav-item selected' : 'nav-item'}><span aria-hidden="true" className="nav-icon">{icons[i]}</span><span className="nav-label">{item}</span></button>)}</nav><div className="sidebar-bottom"><div className="nav-label mb-5 rounded-lg border border-slate-700 p-3"><span className="text-xs font-semibold text-blue-200">Portfolio environment</span><p className="mt-2 text-xs leading-5 text-slate-400">Explore the architecture.<br />Sample data, clearly marked.</p></div><button className="collapse-button" aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed} onClick={() => setCollapsed(!collapsed)}><span aria-hidden="true">{collapsed ? '»' : '«'}</span><span className="nav-label">Collapse navigation</span></button></div></aside>
    <div className="workspace"><header className="topbar"><div className="text-sm text-slate-500">Workspace <span className="mx-2 text-slate-300">/</span><span className="font-medium text-slate-800">{section}</span></div><div className="flex items-center gap-4"><span className="hidden sm:inline text-xs text-slate-500">{loading ? 'Checking session…' : user ? 'Keycloak session' : 'Public portfolio preview'}</span><button className="session-button" disabled={loading} onClick={user ? logout : login}>{user ? 'Sign out' : 'Sign in with Keycloak'} <span aria-hidden="true">↗</span></button></div></header>
    <main id="content" className="content" tabIndex={-1}><div className="mb-7 flex flex-wrap justify-between gap-4 items-start"><div><span className="eyebrow text-slate-500">IDENTITY & ACCESS MANAGEMENT</span><h1 className="mt-2 text-3xl font-semibold tracking-tight">{section === 'Dashboard' ? 'Security overview' : section === 'Identities' ? 'Current Identity' : section}</h1><p className="mt-2 text-sm text-slate-500">Visibility across identities, access and security boundaries.</p></div><Badge>{section === 'Identities' || section === 'Access Explorer' ? 'LIVE API · READ ONLY' : section === 'Lifecycle' ? 'AUTOMATED TEST DEMONSTRATION' : section === 'Integrations' ? 'ARCHITECTURE · NOT LIVE HEALTH' : 'DEMO DATA · PORTFOLIO'}</Badge></div>
    <div className="demo-notice"><span aria-hidden="true">ⓘ</span><p><strong>Demonstration workspace.</strong> Metrics and activity are illustrative, not live backend statistics.</p></div>
    {error && <p role="alert" className="mb-5 rounded-lg bg-amber-50 p-4 text-sm text-amber-900">{error}</p>}
    {user && section !== 'Identities' && <section className="mb-5 rounded-lg border border-blue-200 bg-white p-4 text-sm"><strong>Live session</strong><p className="mt-1 break-all">Signed in as {user.profile.preferred_username ?? user.profile.sub}</p>{principal && <p className="mt-1 break-all text-xs text-slate-500">Internal principal: {principal}</p>}<p className="mt-1 text-slate-600">Your active tenants: {tenants.length ? tenants.join(', ') : 'No tenant information available.'}</p></section>}
    <div className="grid gap-5">{section === 'Dashboard' ? <Dashboard navigate={setSection} /> : section === 'Access Explorer' ? <AccessExplorer user={user} /> : section === 'Identities' ? <CurrentIdentity user={user} principal={principal} tenants={tenants} loading={loading} /> : section === 'Lifecycle' ? <LifecycleOverview /> : <SectionContent section={section} />}</div><footer className="mt-8 flex flex-wrap justify-between gap-2 text-xs text-slate-500"><span>IdentityGuard / Enterprise IAM Reference</span><span>Authentication ≠ authorization</span></footer></main></div></div>;
}
// Single initialization avoids processing the one-use OIDC callback twice in development.
createRoot(document.getElementById('root')!).render(<App />);
