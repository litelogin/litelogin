// LiteLogin's synthetic monitor (Architecture.md, "Synthetic monitoring"):
// it signs in to a dedicated test client as a relying party and its user
// would, and fails if any step does: discovery, JWKS, /authorize, the
// login form, the code exchange (PKCE), /userinfo, a refresh, and
// RP-initiated logout.
//
// It makes plain HTTPS requests, as a browser would, with its own cookie
// jar; redirects are followed by hand, and the one to the client's
// redirect URI isn't followed at all: the code is read from it.
//
// It runs as a Lambda function on a schedule (infra/modules/canary); a run
// that throws is a failed run. Configuration is an SSM SecureString
// parameter (CANARY_PARAMETER) holding JSON: {"issuer", "client_id",
// "redirect_uri", "post_logout_redirect_uri", "email", "password"}. To run
// it locally, put the same JSON in CANARY_CONFIG and run:
// node -e "require('./canary.js').handler()"

const crypto = require('node:crypto');

const TIMEOUT_MS = 10000;

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function step(name, fn) {
  return fn().then(
    (v) => {
      console.log(`ok  ${name}`);
      return v;
    },
    (err) => {
      throw new Error(`${name}: ${err.message}`);
    },
  );
}

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

// A browser: a cookie jar and requests that don't follow redirects.
class Browser {
  constructor(issuer) {
    this.origin = new URL(issuer).origin;
    this.cookies = new Map();
  }

  async request(method, url, { form, headers = {} } = {}) {
    const h = { 'User-Agent': 'LiteLogin-Canary/1', ...headers };
    const u = new URL(url);
    if (u.origin === this.origin && this.cookies.size > 0) {
      h.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    }
    let body;
    if (form) {
      body = new URLSearchParams(form).toString();
      h['Content-Type'] = 'application/x-www-form-urlencoded';
      h.Origin = this.origin;
    }
    const res = await fetch(url, { method, headers: h, body, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (u.origin === this.origin) {
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(';');
        const i = pair.indexOf('=');
        const name = pair.slice(0, i).trim();
        const value = pair.slice(i + 1).trim();
        if (/max-age=0|expires=thu, 01 jan 1970/i.test(c) || value === '') this.cookies.delete(name);
        else this.cookies.set(name, value);
      }
    }
    return { status: res.status, location: res.headers.get('location'), text: await res.text() };
  }

  // Follows redirects on the login host until one leaves it (returned) or
  // a page is served.
  async follow(method, url, opts) {
    let res = await this.request(method, url, opts);
    for (let i = 0; i < 10 && res.status >= 300 && res.status < 400 && res.location; i++) {
      const next = new URL(res.location, url);
      if (next.origin !== this.origin) return { ...res, location: next.toString() };
      url = next.toString();
      res = await this.request('GET', url);
    }
    return res;
  }
}

// unescapeHTML decodes the entities Go's html/template writes in
// attribute values: named ones, and numeric ones such as &#43; for "+".
function unescapeHTML(s) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return String.fromCodePoint(code);
    }
    return named[e.toLowerCase()] ?? m;
  });
}

function hiddenFields(html) {
  const fields = {};
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    fields[m[1]] = unescapeHTML(m[2]);
  }
  return fields;
}

// pageSummary is a page's title and error message, for failure reports.
function pageSummary(html) {
  const title = (html.match(/<title>([^<]*)<\/title>/) || [])[1] || '';
  const error = (html.match(/class="error"[^>]*>([^<]*)</) || [])[1] || '';
  return [title, error].filter(Boolean).join(': ') || html.slice(0, 200);
}

async function getJSON(url, init) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${url}: HTTP ${res.status}, not JSON: ${text.slice(0, 200)}`);
  }
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}: ${text.slice(0, 300)}`);
  return body;
}

function claims(jwt) {
  const parts = jwt.split('.');
  expect(parts.length === 3, 'not a JWT');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
}

async function loadConfig() {
  let raw = process.env.CANARY_CONFIG;
  if (!raw) {
    // The Lambda runtime includes the AWS SDK.
    const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
    const out = await new SSMClient({}).send(new GetParameterCommand({ Name: process.env.CANARY_PARAMETER, WithDecryption: true }));
    raw = out.Parameter.Value;
  }
  const c = JSON.parse(raw);
  for (const k of ['issuer', 'client_id', 'redirect_uri', 'email', 'password']) {
    expect(c[k], `the canary configuration has no ${k}`);
  }
  return c;
}

async function run() {
  const cfg = await loadConfig();
  const issuer = cfg.issuer.replace(/\/$/, '');

  const disco = await step('discovery', () => getJSON(`${issuer}/.well-known/openid-configuration`));
  expect(disco.issuer === issuer, `discovery issuer is ${disco.issuer}, want ${issuer}`);

  const jwks = await step('jwks', () => getJSON(disco.jwks_uri));
  expect(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'no keys in the JWKS');
  const kids = new Set(jwks.keys.map((k) => k.kid));

  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));
  const nonce = b64url(crypto.randomBytes(16));
  const authorize = new URL(disco.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: 'code', client_id: cfg.client_id, redirect_uri: cfg.redirect_uri,
    scope: 'openid email offline_access', state, nonce, prompt: 'login',
    code_challenge: challenge, code_challenge_method: 'S256',
  }).toString();

  const browser = new Browser(issuer);
  const page = await step('authorize', async () => {
    const res = await browser.follow('GET', authorize.toString());
    expect(res.status === 200 && res.text.includes('action="/login"'), `no login form (HTTP ${res.status})`);
    return res;
  });

  const code = await step('login', async () => {
    const form = { ...hiddenFields(page.text), email: cfg.email, password: cfg.password };
    const res = await browser.follow('POST', `${issuer}/login`, { form });
    expect(res.location && res.location.startsWith(cfg.redirect_uri), `not redirected to the client (HTTP ${res.status}): ${pageSummary(res.text)}`);
    const q = new URL(res.location).searchParams;
    expect(!q.get('error'), `authorization error: ${q.get('error')} ${q.get('error_description') || ''}`);
    expect(q.get('state') === state, 'state mismatch');
    expect(q.get('iss') === issuer, `iss parameter is ${q.get('iss')}`);
    expect(q.get('code'), 'no code');
    return q.get('code');
  });

  const tokenRequest = (params) => getJSON(disco.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: cfg.client_id, ...params }).toString(),
  });

  const tokens = await step('token', async () => {
    const t = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: cfg.redirect_uri, code_verifier: verifier });
    expect(t.access_token && t.id_token && t.refresh_token, 'missing tokens');
    const id = claims(t.id_token);
    const header = JSON.parse(Buffer.from(t.id_token.split('.')[0], 'base64url').toString());
    expect(id.iss === issuer && id.aud === cfg.client_id && id.nonce === nonce, 'ID token claims don\'t match the request');
    expect(id.exp * 1000 > Date.now(), 'ID token already expired');
    expect(kids.has(header.kid), `ID token signed with a key (${header.kid}) not in the JWKS`);
    return t;
  });

  await step('userinfo', async () => {
    const u = await getJSON(disco.userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(u.sub === claims(tokens.id_token).sub, 'userinfo sub differs from the ID token');
  });

  await step('refresh', async () => {
    const t = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
    expect(t.access_token && t.refresh_token && t.refresh_token !== tokens.refresh_token, 'refresh token not rotated');
  });

  await step('logout', async () => {
    const end = new URL(disco.end_session_endpoint);
    const params = { client_id: cfg.client_id, id_token_hint: tokens.id_token, state };
    if (cfg.post_logout_redirect_uri) params.post_logout_redirect_uri = cfg.post_logout_redirect_uri;
    end.search = new URLSearchParams(params).toString();
    const confirm = await browser.follow('GET', end.toString());
    expect(confirm.status === 200 && confirm.text.includes('action="/logout"'), `no logout confirmation (HTTP ${confirm.status})`);
    const res = await browser.follow('POST', `${issuer}/logout`, { form: hiddenFields(confirm.text) });
    if (cfg.post_logout_redirect_uri) {
      expect(res.location && res.location.startsWith(cfg.post_logout_redirect_uri), `not returned to the client after logout (HTTP ${res.status})`);
    } else {
      expect(res.status === 200, `logout: HTTP ${res.status}`);
    }
  });
}

exports.handler = async () => {
  await run();
  return 'ok';
};
