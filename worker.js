// UNOFFICIAL community dashboard. Not affiliated with is-a-dev. All rights to the is-a-dev name and logo belong to is-a-dev.
// Cloudflare Worker: GitHub OAuth (code exchange) + a locked-down proxy to the GitHub API.
const GH = 'https://api.github.com';
const ALLOWED = /^\/(user|search\/code|repos\/[\w.-]+\/register(\/.*)?)$/; // only what the dashboard needs
const cookie = (req, n) => (req.headers.get('Cookie') || '').split(/;\s*/).map(c => c.split('=')).find(c => c[0] === n)?.[1];
const setCookie = (n, v, age) => `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === '/auth/login') {
      const state = crypto.randomUUID();
         const p = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, scope: 'public_repo', state });
      return new Response(null, { status: 302, headers: { Location: `https://github.com/login/oauth/authorize?${p}`, 'Set-Cookie': setCookie('gh_state', state, 600) } });
    }

    if (url.pathname === '/auth/callback') {
      if (!url.searchParams.get('code') || url.searchParams.get('state') !== cookie(req, 'gh_state')) return new Response('Invalid OAuth state', { status: 400 });
      const r = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code: url.searchParams.get('code') })
      }).then(r => r.json());
      if (!r.access_token) return new Response('GitHub login failed', { status: 400 });
      const h = new Headers({ Location: '/' });
      h.append('Set-Cookie', setCookie('gh_token', r.access_token, 60 * 60 * 8));
      h.append('Set-Cookie', setCookie('gh_state', '', 0));
      return new Response(null, { status: 302, headers: h });
    }

    if (url.pathname === '/auth/logout') {
      return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': setCookie('gh_token', '', 0) } });
    }

    if (url.pathname.startsWith('/gh/')) {
      const path = url.pathname.slice(3);
      const token = cookie(req, 'gh_token');
      if (!token) return Response.json({ message: 'Not signed in' }, { status: 401 });
      if (!ALLOWED.test(path)) return Response.json({ message: 'Path not allowed' }, { status: 403 });
      const write = !['GET', 'HEAD'].includes(req.method);
      if (write && req.headers.get('X-Requested-With') !== 'dashboard') return Response.json({ message: 'Bad request' }, { status: 403 }); // CSRF guard
      const r = await fetch(GH + path + url.search, {
        method: req.method, body: write ? await req.text() : undefined,
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'unofficial-isadev-dashboard', 'Content-Type': 'application/json' }
      });
      const h = new Headers({ 'Content-Type': r.headers.get('Content-Type') || 'application/json' });
      if (r.status === 401) h.set('Set-Cookie', setCookie('gh_token', '', 0));
      return new Response(r.status === 204 ? null : r.body, { status: r.status, headers: h });
    }

    return env.ASSETS.fetch(req);
  }
};
