import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

// Local reference deployment. Tokens are stored in sessionStorage, not localStorage.
// A production high-security deployment should evaluate a BFF and HttpOnly cookies.
export const auth = new UserManager({
  authority: 'http://localhost:8081/realms/iam-reference',
  client_id: 'iam-web',
  redirect_uri: 'http://localhost:3000/auth/callback',
  post_logout_redirect_uri: 'http://localhost:3000/',
  response_type: 'code',
  scope: 'openid profile email',
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  automaticSilentRenew: false
});
