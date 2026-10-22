export type Session = { access_token: string; expired?: boolean } | null;
export class ApiError extends Error {}
export function outcome(status: number): string {
  return ({401: 'Authentication required', 403: 'Access denied', 404: 'Resource not found', 503: 'Authorization service unavailable'} as Record<number, string>)[status] ?? 'Request could not be completed';
}
export async function apiRead(path: string, session: Session, signal?: AbortSignal): Promise<unknown> {
  if (!session || session.expired || !session.access_token) throw new ApiError('Authentication required');
  if (!/^\/api\/v1\/(me|(?:projects|documents)\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/.test(path)) throw new ApiError('Invalid resource identifier');
  const timeout = AbortSignal.timeout(10000);
  const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  try {
    const response = await fetch(path, { method: 'GET', headers: { Authorization: `Bearer ${session.access_token}` }, credentials: 'omit', redirect: 'error', cache: 'no-store', signal: requestSignal });
    if (response.status !== 200) throw new ApiError(outcome(response.status));
    return await response.json();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('Request could not be completed');
  }
}
export type Resource = { id: string; tenantId: string; tenantSlug: string; name: string };
export function resourceData(value: unknown, id: string): Resource {
  const r = value as Partial<Resource> | null;
  if (!r || typeof r !== 'object' || typeof r.id !== 'string' || r.id.toLowerCase() !== id.toLowerCase() || !['tenantId','tenantSlug','name'].every(k => typeof (r as Record<string, unknown>)[k] === 'string')) throw new ApiError('Resource response unavailable');
  return { id: r.id, tenantId: r.tenantId!, tenantSlug: r.tenantSlug!, name: r.name! };
}
