import { useEffect, useRef, useState } from 'react';
import type { User } from 'oidc-client-ts';
import { apiRead, resourceData, type Resource } from './api';
export function AccessExplorer({ user }: { user: User | null }) {
  const [kind, setKind] = useState('projects');
  const [id, setId] = useState('');
  const [resource, setResource] = useState<Resource | null>(null);
  const [message, setMessage] = useState('Enter a resource UUID to inspect access.');
  const [loading, setLoading] = useState(false);
  const pending = useRef<AbortController | null>(null);
  useEffect(() => {
    setResource(null); setLoading(false); setMessage('Enter a resource UUID to inspect access.');
    return () => pending.current?.abort();
  }, [user]);
  async function inspect(event: React.FormEvent) {
    event.preventDefault(); pending.current?.abort();
    const request = new AbortController(); pending.current = request;
    setResource(null); setLoading(true); setMessage('Checking resource access…');
    try {
      const result = resourceData(await apiRead(`/api/v1/${kind}/${id.trim()}`, user, request.signal), id.trim());
      if (!request.signal.aborted) { setResource(result); setMessage('Resource available'); }
    } catch (error) {
      if (!request.signal.aborted) setMessage(error instanceof Error ? error.message : 'Request could not be completed');
    } finally { if (!request.signal.aborted) setLoading(false); }
  }
  return <section className="panel p-6"><span className="eyebrow text-blue-600">LIVE API · READ ONLY</span><h2 className="mt-3 text-xl">Protected resource lookup</h2><p className="mt-2 text-sm text-slate-500">The server determines access and resource tenancy. No demo responses are used.</p>
    {!user ? <p role="status" className="mt-6">Authentication required. Sign in with Keycloak to continue.</p> : <>
      <form onSubmit={inspect} className="mt-6 flex flex-wrap gap-3 items-end">
        <label className="text-sm">Resource type<select className="block border rounded p-2 mt-2" value={kind} onChange={e => {setKind(e.target.value); setResource(null); setMessage('Enter a resource UUID to inspect access.');}} disabled={loading}><option value="projects">Project</option><option value="documents">Document</option></select></label>
        <label className="text-sm grow">Resource UUID<input required autoComplete="off" spellCheck={false} className="block border rounded p-2 mt-2 w-full" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value={id} disabled={loading} onChange={e => {setId(e.target.value);setResource(null);setMessage('Enter a resource UUID to inspect access.');}} /></label>
        <button className="session-button" disabled={loading}>{loading ? 'Checking…' : 'Check access'}</button>
      </form><p role="status" aria-live="polite" className="mt-5 text-sm">{message}</p>
      {resource && <dl className="mt-5 grid gap-3 text-sm rounded-lg bg-slate-50 p-5 break-words">{Object.entries({Name: resource.name, ID: resource.id, Tenant: resource.tenantSlug}).map(([key,value]) => <div key={key}><dt className="text-slate-500">{key}</dt><dd className="font-medium mt-1">{value}</dd></div>)}</dl>}
    </>}
  </section>;
}
