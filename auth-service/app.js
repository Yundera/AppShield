const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Issuer, generators } = require('openid-client');

const app = express();
const PORT = 9999;

// Configuration from environment
const USERNAME = process.env.USER || '';
const PASSWORD = process.env.PASSWORD || '';
const AUTH_HASH = process.env.AUTH_HASH || '';
const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS || '720', 10);
const SESSION_DURATION_MS = SESSION_DURATION_HOURS * 60 * 60 * 1000;
// OIDC mode is enabled whenever OIDC_REGISTRAR_URL is set — no separate toggle.
// The registrar must be reachable on the `pcs` docker network (e.g. http://auth-registrar:9092).
const OIDC_REGISTRAR_URL = (process.env.OIDC_REGISTRAR_URL || '').replace(/\/+$/, '');
const OIDC_ENABLED = OIDC_REGISTRAR_URL.length > 0;

// --- Public host set (multi-domain SSO) -------------------------------------
// AppShield is reachable under several hostnames: the custom user domain plus
// the IP-based nip.io / sslip.io fallbacks. We register an OIDC callback for ALL
// of them, then pick the redirect_uri matching the host the user actually
// arrived on — so a login on <app>-<userdomain> returns there, and a login on
// the sslip.io host returns there. Hosts are computed with the SAME formula as
// the Caddy labels and the mesh-router-auth registrar — keep the three in sync
// (see SSO/AppShield host-formula doc). When DOMAIN/PUBLIC_IP_DASH aren't
// injected, the set is empty and we fall back to the legacy request-Host behaviour.
const APP_NAME = (process.env.APP_NAME || os.hostname() || '').toLowerCase();
const DOMAIN = (process.env.DOMAIN || '').toLowerCase();
const PUBLIC_IP_DASH = (process.env.PUBLIC_IP_DASH || '').toLowerCase();
const DEFAULT_APP_HOST_TEMPLATES = ['{APP}-{DOMAIN}', '{APP}-{IP_DASH}.nip.io', '{APP}-{IP_DASH}.sslip.io'];
const APP_HOST_TEMPLATES = (() => {
    const raw = process.env.APP_HOST_TEMPLATES;
    if (!raw) return DEFAULT_APP_HOST_TEMPLATES;
    try {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr) && arr.length && arr.every((s) => typeof s === 'string' && s)) return arr;
    } catch { /* fall through to warning */ }
    console.warn('[Auth Service] APP_HOST_TEMPLATES must be a JSON string array — using defaults');
    return DEFAULT_APP_HOST_TEMPLATES;
})();
const CALLBACK_PATH = '/nhl-auth/oidc/callback';

function computeAppHosts(appName) {
    const subst = { '{APP}': appName, '{DOMAIN}': DOMAIN, '{IP_DASH}': PUBLIC_IP_DASH };
    const hosts = [];
    for (const tpl of APP_HOST_TEMPLATES) {
        if (tpl.includes('{DOMAIN}') && !DOMAIN) continue;
        if (tpl.includes('{IP_DASH}') && !PUBLIC_IP_DASH) continue;
        let h = tpl;
        for (const [k, v] of Object.entries(subst)) h = h.split(k).join(v);
        hosts.push(h.toLowerCase());
    }
    return hosts;
}

const APP_HOSTS = APP_NAME ? computeAppHosts(APP_NAME) : [];
const ALLOWED_ORIGINS = new Set(APP_HOSTS.map((h) => `https://${h}`));
// Preferred origin when a request arrives on a host we don't recognise.
const CANONICAL_ORIGIN = APP_HOSTS.length ? `https://${APP_HOSTS[0]}` : null;
if (OIDC_ENABLED) {
    console.log(`[Auth Service] app=${APP_NAME} public hosts: ${APP_HOSTS.join(', ') || '(none — falling back to request Host)'}`);
}

// External credential validation (MACHINE / API, no redirect). When set, an
// Authorization header (HTTP Basic `user:pass` or `Bearer <token>`) that does NOT
// match the static AUTH_HASH is forwarded to this URL for verification — e.g. the
// casaos-oidc-bridge `/validate` endpoint, which checks it against CasaOS. This lets
// API clients authenticate with their real CasaOS identity instead of (or alongside)
// a shared AUTH_HASH. It is product-agnostic: AppShield only knows "POST the header
// here, 200 = valid". The validator must be an internal-only endpoint — the bridge
// serves /validate on a pcs-network-only port — so no shared secret is needed.
const CREDENTIAL_VALIDATE_URL = (process.env.CREDENTIAL_VALIDATE_URL || '').replace(/\/+$/, '');
const CREDENTIAL_CACHE_TTL_MS = parseInt(process.env.CREDENTIAL_CACHE_TTL_SECONDS || '60', 10) * 1000;
// Cache of validated Authorization headers: sha256(header) -> expiry. Avoids calling
// the validator (and CasaOS) on every request from a machine that re-sends creds.
const credCache = new Map();

// Validate an Authorization header against the external validator, with caching.
async function validateCredentialHeader(authHeader) {
    if (!CREDENTIAL_VALIDATE_URL || !authHeader) return false;
    const key = crypto.createHash('sha256').update(authHeader).digest('hex');
    const cached = credCache.get(key);
    if (cached) {
        if (cached > Date.now()) return true;
        credCache.delete(key);
    }
    try {
        const resp = await fetch(CREDENTIAL_VALIDATE_URL, { method: 'POST', headers: { 'Authorization': authHeader } });
        if (resp.ok) {
            if (CREDENTIAL_CACHE_TTL_MS > 0) credCache.set(key, Date.now() + CREDENTIAL_CACHE_TTL_MS);
            return true;
        }
    } catch (e) {
        console.log(`[Auth Service] Credential validation error: ${e.message}`);
    }
    return false;
}

// Generate password hash for session validation
// When password changes (container restart), password-based sessions become invalid
const PASSWORD_HASH = crypto.createHash('sha256').update(PASSWORD + USERNAME).digest('hex');

// In-memory session store
// Format: { sessionId: { expires: timestamp, passwordHash?: string, authHash?: string, oidcSub?: string } }
const sessions = {};

// OIDC state: the client is lazy-initialized on the first /oidc/login request, because we
// need the public Host header to compute the redirect URI before calling the registrar.
let oidcClient = null;
let oidcIssuerUrl = null;

// Pending authorization-code flows keyed by OAuth `state`: { codeVerifier, originalUri, createdAt }
const pendingOidcFlows = new Map();
const OIDC_FLOW_TTL_MS = 10 * 60 * 1000;

// Generate secure random session ID
function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// Cleanup expired sessions every hour
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [sessionId, session] of Object.entries(sessions)) {
        if (session.expires < now) {
            delete sessions[sessionId];
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[Auth Service] Cleaned up ${cleaned} expired sessions`);
    }
}, 60 * 60 * 1000);

// Cleanup stale pending OIDC flows every 5 minutes
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [state, flow] of pendingOidcFlows) {
        if (now - flow.createdAt > OIDC_FLOW_TTL_MS) {
            pendingOidcFlows.delete(state);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[Auth Service] Cleaned up ${cleaned} stale OIDC flows`);
    }
}, 5 * 60 * 1000);

function getPublicOrigin(req) {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const host = req.headers['x-forwarded-host'] || req.headers['host'];
    if (!host) {
        throw new Error('Cannot determine public origin: no Host header');
    }
    return `${proto}://${host}`;
}

// Pick the callback URL for the host the request arrived on. Falls back to the
// canonical host for an unrecognised host, and to the raw request origin when no
// host set was configured (legacy single-host behaviour).
function chosenRedirect(req) {
    const origin = getPublicOrigin(req);
    const base = ALLOWED_ORIGINS.has(origin) ? origin : (CANONICAL_ORIGIN || origin);
    return `${base}${CALLBACK_PATH}`;
}

async function getOrInitOidcClient(publicOrigin) {
    if (oidcClient) return oidcClient;

    // Register a callback for EVERY host AppShield is reachable under, so any of
    // them is an accepted redirect_uri (the registrar verifies each against its
    // own recomputed allowlist). Falls back to the single request origin when no
    // host set is configured (DOMAIN/PUBLIC_IP_DASH not injected).
    const callbacks = ALLOWED_ORIGINS.size > 0
        ? [...ALLOWED_ORIGINS].map((o) => `${o}${CALLBACK_PATH}`)
        : [`${publicOrigin}${CALLBACK_PATH}`];
    console.log(`[Auth Service] Registering OIDC client with ${OIDC_REGISTRAR_URL} (callbacks=${callbacks.join(', ')})`);

    const response = await fetch(`${OIDC_REGISTRAR_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: callbacks }),
    });
    if (!response.ok) {
        const body = await response.text();
        throw new Error(`Registrar returned ${response.status}: ${body}`);
    }
    const { client_id, client_secret, issuer_url } = await response.json();
    console.log(`[Auth Service] Registered OIDC client_id=${client_id} issuer=${issuer_url}`);

    const issuer = await Issuer.discover(issuer_url);
    oidcClient = new issuer.Client({
        client_id,
        client_secret,
        redirect_uris: callbacks,
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
    });
    oidcIssuerUrl = issuer_url;
    return oidcClient;
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve login page
app.get('/login', (req, res) => {
    const loginHtmlPath = path.join(__dirname, '../login.html');

    if (fs.existsSync(loginHtmlPath)) {
        res.sendFile(loginHtmlPath);
    } else {
        // Fallback inline login page if file doesn't exist
        res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Login Required</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 3rem;
            max-width: 400px;
            width: 90%;
        }
        h1 { color: #2c3e50; margin-bottom: 2rem; text-align: center; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; color: #2c3e50; font-weight: 500; }
        input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 1rem;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        .error { color: #e74c3c; margin-top: 1rem; text-align: center; }
        .footer {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #ecf0f1;
            color: #95a5a6;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.75rem;
        }
        .footer-logo {
            width: 120px;
            height: auto;
            opacity: 0.7;
            transition: opacity 0.3s;
        }
        .footer-logo:hover {
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Login Required</h1>
        <form method="POST" action="/nhl-auth/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <input type="hidden" name="redirect" value="/">
            <button type="submit">Login</button>
            <div class="error" id="error"></div>
        </form>
        <div class="footer">
            <svg class="footer-logo" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 330.68923 161.53949"><defs><linearGradient id="d" x1="28.41308" y1="24.34637" x2="119.03571" y2="114.96899" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#27b4e1"/><stop offset=".0935" stop-color="#3da4d5"/><stop offset=".41983" stop-color="#8870ae"/><stop offset=".69027" stop-color="#bf4a92"/><stop offset=".89107" stop-color="#e13281"/><stop offset="1" stop-color="#ee2a7b"/></linearGradient></defs><g><path d="M107.81025,100.86073l6.40941.05962c16.66759,0,30.17937-13.51171,30.17937-30.1793s-13.51178-30.1793-30.17937-30.1793c-1.51561,0-3.0042.11478-4.45984.33045.06712-.86962.11199-1.74544.11199-2.63229,0-18.64504-15.1148-33.75991-33.75991-33.75991-17.83852,0-32.43546,13.83828-33.6659,31.36378-1.6969-.27143-3.43574-.41718-5.20917-.41718-18.08006,0-32.73684,14.65678-32.73684,32.73691,0,16.69318,12.57326,32.47318,28.64476,32.47318l7.71007.07145" style="fill:#dcebf9; stroke:url(#d); stroke-linecap:round; stroke-linejoin:round; stroke-width:9px;"/><path d="M102.9618,76.11709l-26.48454,32.23774c-1.14171,1.38972-1.7722,3.12901-1.78623,4.92752l-.24151,22.92321" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:10px;"/><line x1="65.9599" y1="99.84852" x2="45.93722" y2="75.47637" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:10px;"/><circle cx="74.44951" cy="147.53169" r="8.48961" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:9px;"/><rect x="90.48678" y="91.18463" width="240.20245" height="53.06293" style="fill:none;"/><path d="M109.6869,144.49847c-2.76025,0-5.23047-.58984-7.41016-1.76953-2.18066-1.17969-3.8999-2.91016-5.16016-5.19043-1.25977-2.27979-1.88965-5.0791-1.88965-8.3999v-14.75977c0-.87939.28955-1.60986.86963-2.18994.57959-.57959,1.31006-.87012,2.18994-.87012.87939,0,1.60986.29053,2.19043.87012.5791.58008.86963,1.31055.86963,2.18994v14.75977c0,2.24072.41992,4.09033,1.26025,5.55029.83984,1.46045,1.97998,2.54053,3.41992,3.23975,1.43994.7002,3.06006,1.0498,4.85986,1.0498,1.71924,0,3.24951-.33936,4.59033-1.02002,1.33936-.67969,2.40918-1.59912,3.20996-2.75977.79932-1.15967,1.19971-2.45996,1.19971-3.8999h3.78027c0,2.48047-.61035,4.72021-1.83008,6.71973-1.2207,2.00098-2.87988,3.58057-4.97998,4.73975-2.1001,1.16113-4.49072,1.74023-7.16992,1.74023ZM122.94667,144.19867c-.88037,0-1.61035-.29004-2.18994-.87012-.58057-.5791-.87012-1.30957-.87012-2.18945v-26.76025c0-.91992.28955-1.65967.87012-2.22021.57959-.55957,1.30957-.83984,2.18994-.83984.91992,0,1.65918.28027,2.22021.83984.55957.56055.83984,1.30029.83984,2.22021v26.76025c0,.87988-.28027,1.61035-.83984,2.18945-.56104.58008-1.30029.87012-2.22021.87012Z" style="fill:#294056;"/><path d="M139.8661,144.25824c-.88037,0-1.61035-.28906-2.18994-.86914-.58057-.58008-.87012-1.31055-.87012-2.19043v-26.75977c0-.91992.28955-1.65967.87012-2.22021.57959-.55957,1.30957-.83984,2.18994-.83984.91992,0,1.65918.28027,2.22021.83984.55957.56055.83984,1.30029.83984,2.22021v26.75977c0,.87988-.28027,1.61035-.83984,2.19043-.56104.58008-1.30029.86914-2.22021.86914ZM164.52626,144.25824c-.88037,0-1.61084-.28906-2.18994-.86914-.58057-.58008-.87012-1.31055-.87012-2.19043v-14.75977c0-2.28027-.41992-4.14014-1.26025-5.58008-.83984-1.43994-1.97021-2.50977-3.38965-3.20996-1.42041-.69971-3.05078-1.05029-4.89014-1.05029-1.68018,0-3.20068.34033-4.56006,1.02002-1.36035.68066-2.44043,1.58984-3.23975,2.72998-.80078,1.14014-1.2002,2.45068-1.2002,3.93018h-3.77979c0-2.52002.60938-4.77002,1.82959-6.75,1.21973-1.97998,2.88965-3.54932,5.01025-4.70996,2.11963-1.15967,4.5-1.74023,7.14014-1.74023,2.75977,0,5.229.59082,7.40967,1.77002,2.17969,1.18018,3.8999,2.91016,5.16016,5.18994,1.25977,2.28027,1.89014,5.08057,1.89014,8.40039v14.75977c0,.87988-.29102,1.61035-.87012,2.19043-.58057.58008-1.31055.86914-2.18994.86914Z" style="fill:#294056;"/><path d="M192.60633,144.4389c-3.12012,0-5.93066-.72949-8.43066-2.19043-2.5-1.45947-4.47949-3.44971-5.93945-5.96973-1.46094-2.52002-2.19043-5.35986-2.19043-8.52002,0-3.15967.66992-5.98975,2.01074-8.49023,1.33887-2.49902,3.16895-4.479,5.48926-5.93994,2.31934-1.45947,4.94043-2.18994,7.86035-2.18994,2.35938,0,4.53906.49023,6.54004,1.47021,2,.98047,3.67969,2.31006,5.04004,3.98975v-16.19971c0-.91992.28906-1.65967.87012-2.22021.5791-.55957,1.30957-.83984,2.18945-.83984.91992,0,1.65918.28027,2.2207.83984.55957.56055.83984,1.30029.83984,2.22021v27.35986c0,3.16016-.73047,6-2.19043,8.52002-1.46094,2.52002-3.42969,4.51025-5.91016,5.96973-2.48047,1.46094-5.2793,2.19043-8.39941,2.19043ZM192.60633,139.03851c2.04004,0,3.85938-.48926,5.45996-1.46973,1.59961-.97998,2.85938-2.32959,3.7793-4.05029.91992-1.71924,1.38086-3.63916,1.38086-5.75977,0-2.16016-.46094-4.08008-1.38086-5.76025-.91992-1.67969-2.17969-3.00928-3.7793-3.98975-1.60059-.97998-3.41992-1.47021-5.45996-1.47021-2.00098,0-3.81055.49023-5.43066,1.47021-1.61914.98047-2.90039,2.31006-3.83984,3.98975-.94043,1.68018-1.41016,3.6001-1.41016,5.76025,0,2.12061.46973,4.04053,1.41016,5.75977.93945,1.7207,2.2207,3.07031,3.83984,4.05029,1.62012.98047,3.42969,1.46973,5.43066,1.46973Z" style="fill:#294056;"/><path d="M235.32606,144.4389c-3.32129,0-6.27051-.70996-8.85059-2.12988s-4.59961-3.37988-6.05957-5.88037c-1.46094-2.49951-2.19043-5.37012-2.19043-8.60986,0-3.2793.69043-6.16992,2.07031-8.66992,1.37988-2.49951,3.29004-4.45996,5.72949-5.88037,2.43945-1.41943,5.24023-2.12988,8.40039-2.12988,3.12012,0,5.7998.68994,8.04004,2.06982,2.23926,1.38037,3.9502,3.28076,5.12988,5.7002,1.17969,2.4209,1.77051,5.21045,1.77051,8.37012,0,.76025-.26074,1.39014-.78027,1.89014-.52051.50049-1.18066.75-1.98047.75h-24.17969v-4.80029h24l-2.45996,1.68018c-.04004-2-.44043-3.78955-1.2002-5.37012-.75977-1.57959-1.83984-2.82959-3.24023-3.75-1.40039-.91943-3.09961-1.37988-5.09961-1.37988-2.28027,0-4.22949.50049-5.84961,1.5-1.62012,1-2.85059,2.37012-3.69043,4.10986-.83984,1.74023-1.25977,3.71045-1.25977,5.91016,0,2.2002.5,4.16064,1.5,5.87988.99902,1.72021,2.37891,3.08057,4.13965,4.08008,1.75977,1,3.78027,1.5,6.06055,1.5,1.23926,0,2.50977-.22998,3.80957-.68994,1.2998-.45947,2.34961-.99023,3.15039-1.59033.59961-.43945,1.24902-.66895,1.9502-.68994.69922-.01953,1.30957.19043,1.8291.63037.67969.59961,1.04004,1.25977,1.08008,1.97998.04004.71973-.28027,1.34033-.95996,1.85986-1.36035,1.08008-3.05078,1.95996-5.06934,2.63965-2.02051.68066-3.95117,1.02051-5.79004,1.02051Z" style="fill:#294056;"/><path d="M260.16493,144.19867c-.95996,0-1.70117-.24902-2.2207-.75-.51953-.5-.7793-1.25-.7793-2.25v-26.81982c0-.95996.25977-1.69971.7793-2.22021.51953-.51953,1.26074-.77979,2.2207-.77979.99902,0,1.74902.25,2.25.75.49902.50049.75,1.25049.75,2.25v26.81982c0,.95996-.25098,1.7002-.75,2.21973-.50098.52051-1.25098.78027-2.25.78027ZM260.10438,123.67865c0-2.3999.58984-4.5498,1.77051-6.4502,1.17871-1.89893,2.76855-3.40967,4.76953-4.52979,2-1.11914,4.2002-1.68018,6.60059-1.68018,2.39941,0,4.18945.39014,5.36914,1.17041,1.17969.77979,1.62988,1.70996,1.35059,2.78955-.12012.56104-.35059.99023-.69043,1.29004-.33984.30029-.73047.49072-1.16992.57031-.44043.08057-.9209.06006-1.43945-.06006-2.56055-.51953-4.86035-.55957-6.90039-.12012-2.04004.44043-3.65039,1.26025-4.83008,2.45996-1.18066,1.2002-1.76953,2.7207-1.76953,4.56006h-3.06055Z" style="fill:#294056;"/><path d="M297.60438,144.4389c-2.91992,0-5.54102-.72949-7.86035-2.19043-2.32031-1.45947-4.15039-3.43945-5.48926-5.93994-1.34082-2.49902-2.01074-5.32959-2.01074-8.48975,0-3.15967.72949-6,2.19043-8.52002,1.45996-2.52002,3.43945-4.50928,5.93945-5.97021,2.5-1.45947,5.31055-2.18994,8.43066-2.18994s5.91895.73047,8.39941,2.18994c2.48047,1.46094,4.44922,3.4502,5.91016,5.97021,1.45996,2.52002,2.19043,5.36035,2.19043,8.52002h-2.33984c0,3.16016-.6709,5.99072-2.01074,8.48975-1.33984,2.50049-3.16992,4.48047-5.48926,5.93994-2.32031,1.46094-4.94141,2.19043-7.86035,2.19043ZM298.80458,139.03851c2.04004,0,3.85938-.48926,5.45996-1.46973,1.59961-.97998,2.85938-2.31934,3.7793-4.02002.91992-1.69971,1.38086-3.60938,1.38086-5.72998,0-2.16016-.46094-4.08936-1.38086-5.79004-.91992-1.69971-2.17969-3.03955-3.7793-4.02002-1.60059-.97998-3.41992-1.47021-5.45996-1.47021-2.00098,0-3.81055.49023-5.43066,1.47021-1.61914.98047-2.90039,2.32031-3.83984,4.02002-.94043,1.70068-1.41016,3.62988-1.41016,5.79004,0,2.12061.46973,4.03027,1.41016,5.72998.93945,1.70068,2.2207,3.04004,3.83984,4.02002,1.62012.98047,3.42969,1.46973,5.43066,1.46973ZM312.24403,144.25824c-.87988,0-1.61035-.28906-2.18945-.86914-.58105-.58008-.87012-1.31055-.87012-2.19043v-9.18018l1.13965-6.35986,4.98047,2.16016v13.37988c0,.87988-.29102,1.61035-.87012,2.19043-.58008.58008-1.31055.86914-2.19043.86914Z" style="fill:#294056;"/></g></svg>
            <div>Protected by Nginx Hash Lock - Credential-Based Authentication</div>
        </div>
    </div>
    <script>
        const params = new URLSearchParams(window.location.search);
        if (params.get('error') === 'invalid') {
            document.getElementById('error').textContent = 'Invalid username or password';
        }
        if (params.get('redirect')) {
            document.querySelector('input[name="redirect"]').value = params.get('redirect');
        }
    </script>
</body>
</html>
        `);
    }
});

// Handle login submission
app.post('/nhl-auth/login', async (req, res) => {
    const { username, password, redirect } = req.body;
    const startTime = Date.now();

    // Validate credentials
    const isValid = username === USERNAME && password === PASSWORD;

    if (isValid) {
        // Create session
        const sessionId = generateSessionId();
        sessions[sessionId] = {
            expires: Date.now() + SESSION_DURATION_MS,
            passwordHash: PASSWORD_HASH
        };

        console.log(`[Auth Service] Login successful for user: ${username}`);
        console.log(`[Auth Service] Session created: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

        // Set cookie and redirect
        res.cookie('appshield_session', sessionId, {
            httpOnly: true,
            secure: false, // Set to true if using HTTPS
            maxAge: SESSION_DURATION_MS,
            sameSite: 'lax'
        });

        res.redirect(redirect || '/');
    } else {
        // Apply 2-second delay for failed attempts (anti-brute force)
        const elapsed = Date.now() - startTime;
        const delay = Math.max(0, 2000 - elapsed);

        console.log(`[Auth Service] Login failed for user: ${username || '(empty)'}`);

        setTimeout(() => {
            res.redirect('/login?error=invalid' + (redirect ? `&redirect=${encodeURIComponent(redirect)}` : ''));
        }, delay);
    }
});

// Auth check endpoint (called by nginx auth_request)
app.get('/nhl-auth/check', async (req, res) => {
    // Check for existing session first
    let sessionId = req.cookies.appshield_session;

    if (sessionId && sessions[sessionId]) {
        const session = sessions[sessionId];

        // Check if session is expired
        if (session.expires < Date.now()) {
            console.log(`[Auth Service] Auth check failed: Session expired (${sessionId.substring(0, 8)}...)`);
            delete sessions[sessionId];
            // Continue to check other auth methods
        }
        // Check if credentials are still valid
        else {
            // Session is valid if ANY of: password hash, auth hash, or OIDC sub is set.
            // OIDC sessions are trusted until expiry — there's no local credential to re-verify.
            const passwordValid = session.passwordHash && session.passwordHash === PASSWORD_HASH;
            const authHashValid = session.authHash && session.authHash === AUTH_HASH;
            const oidcValid = !!session.oidcSub;

            if (passwordValid || authHashValid || oidcValid) {
                console.log(`[Auth Service] Auth check passed via session (${sessionId.substring(0, 8)}...)`);
                return res.status(200).send('OK');
            } else {
                console.log(`[Auth Service] Auth check failed: Credentials changed, invalidating session (${sessionId.substring(0, 8)}...)`);
                delete sessions[sessionId];
                // Continue to check other auth methods
            }
        }
    }

    // No valid session - check if hash parameter is valid
    if (process.env.AUTH_HASH) {
        const originalUri = req.headers['x-original-uri'] || '';
        const hashMatch = originalUri.match(/[?&]hash=([^&]+)/);

        if (hashMatch && hashMatch[1] === process.env.AUTH_HASH) {
            console.log('[Auth Service] Auth check passed via hash parameter');

            // Create a new session only if one doesn't exist
            if (!sessionId || !sessions[sessionId]) {
                sessionId = generateSessionId();
                sessions[sessionId] = {
                    expires: Date.now() + SESSION_DURATION_MS,
                    authHash: AUTH_HASH
                };

                console.log(`[Auth Service] Session created for hash auth: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

                // Set session cookie
                res.cookie('appshield_session', sessionId, {
                    httpOnly: true,
                    secure: false,
                    maxAge: SESSION_DURATION_MS,
                    sameSite: 'lax'
                });
            }

            return res.status(200).send('OK');
        }
    }

    // No valid session — check the AUTH_HASH carried in the Authorization header.
    // Machine / API clients (non-interactive) present the hash as either an HTTP
    // Basic credential (true basic auth, e.g. `curl -u any:<hash>`) or a Bearer
    // token. Validated against AUTH_HASH only — never USER/PASSWORD, which are the
    // interactive (human) modes. Stateless: no session cookie is minted, the client
    // simply re-sends the header on each request.
    if (process.env.AUTH_HASH) {
        const authHeader = req.headers['authorization'] || '';
        let headerHashOk = false;
        if (/^Bearer /i.test(authHeader)) {
            headerHashOk = authHeader.slice(7).trim() === process.env.AUTH_HASH;
        } else if (/^Basic /i.test(authHeader)) {
            try {
                const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8');
                const sep = decoded.indexOf(':');
                const user = sep >= 0 ? decoded.slice(0, sep) : decoded;
                const pass = sep >= 0 ? decoded.slice(sep + 1) : '';
                // Accept the hash as either field so `-u <hash>:` and `-u any:<hash>` both work.
                headerHashOk = pass === process.env.AUTH_HASH || user === process.env.AUTH_HASH;
            } catch (e) { /* malformed base64 — treat as no match */ }
        }
        if (headerHashOk) {
            console.log('[Auth Service] Auth check passed via Authorization header (hash)');
            return res.status(200).send('OK');
        }
    }

    // Static hash didn't match — delegate the Authorization header to the external
    // credential validator (e.g. the CasaOS bridge /validate) for real per-user API
    // identity. Basic (user:pass) and Bearer (token) are both handled by the validator.
    if (CREDENTIAL_VALIDATE_URL) {
        const authHeader = req.headers['authorization'] || '';
        if (authHeader && await validateCredentialHeader(authHeader)) {
            console.log('[Auth Service] Auth check passed via external credential validation');
            return res.status(200).send('OK');
        }
    }

    // Check session cookie again (for cases where hash auth wasn't valid)
    sessionId = req.cookies.appshield_session;

    if (!sessionId) {
        console.log('[Auth Service] Auth check failed: No session cookie and no valid hash');
        return res.status(401).send('Unauthorized');
    }

    const session = sessions[sessionId];

    if (!session) {
        console.log(`[Auth Service] Auth check failed: Session not found (${sessionId.substring(0, 8)}...)`);
        return res.status(401).send('Unauthorized');
    }

    if (session.expires < Date.now()) {
        console.log(`[Auth Service] Auth check failed: Session expired (${sessionId.substring(0, 8)}...)`);
        delete sessions[sessionId];
        return res.status(401).send('Unauthorized');
    }

    // Check if password has changed
    if (session.passwordHash && session.passwordHash !== PASSWORD_HASH) {
        console.log(`[Auth Service] Auth check failed: Password changed, invalidating session (${sessionId.substring(0, 8)}...)`);
        delete sessions[sessionId];
        return res.status(401).send('Unauthorized');
    }

    // Session is valid
    console.log(`[Auth Service] Auth check passed via session (${sessionId.substring(0, 8)}...)`);
    res.status(200).send('OK');
});

// Establish session endpoint (for hash authentication to set cookies properly)
app.get('/nhl-auth/establish-session', (req, res) => {
    // Check if hash parameter is valid
    if (process.env.AUTH_HASH) {
        const hash = req.query.hash;
        let returnTo = req.query.return_to || '/';

        // Strip hash parameter from return URL to prevent redirect loop
        returnTo = returnTo.replace(/[?&]hash=[^&]+(&|$)/, (match, p1) => p1 === '&' ? '&' : '?').replace(/[?&]$/, '').replace(/\?$/, '') || '/';

        if (hash && hash === process.env.AUTH_HASH) {
            // Check if session already exists
            let sessionId = req.cookies.appshield_session;

            if (sessionId && sessions[sessionId]) {
                const session = sessions[sessionId];
                // Check if session is valid (not expired and credentials are still valid)
                const passwordValid = session.passwordHash && session.passwordHash === PASSWORD_HASH;
                const authHashValid = session.authHash && session.authHash === AUTH_HASH;

                if (session.expires > Date.now() && (passwordValid || authHashValid)) {
                    // Valid session already exists
                    console.log(`[Auth Service] Session already valid: ${sessionId.substring(0, 8)}...`);
                    // Redirect back if requested
                    if (req.query.return_to) {
                        return res.redirect(returnTo);
                    }
                    return res.status(200).json({ status: 'ok', message: 'Session already valid' });
                } else {
                    // Session expired or password changed, delete it
                    delete sessions[sessionId];
                }
            }

            // Create new session
            sessionId = generateSessionId();
            sessions[sessionId] = {
                expires: Date.now() + SESSION_DURATION_MS,
                authHash: AUTH_HASH
            };

            console.log(`[Auth Service] Session established via hash: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

            // Set session cookie
            res.cookie('appshield_session', sessionId, {
                httpOnly: true,
                secure: false,
                maxAge: SESSION_DURATION_MS,
                sameSite: 'lax'
            });

            // Redirect back if requested
            if (req.query.return_to) {
                return res.redirect(returnTo);
            }

            return res.status(200).json({ status: 'ok', message: 'Session established' });
        }
    }

    return res.status(401).json({ status: 'error', message: 'Invalid or missing hash' });
});

// Start OIDC authorization_code + PKCE flow
app.get('/nhl-auth/oidc/login', async (req, res) => {
    if (!OIDC_ENABLED) {
        return res.status(404).send('OIDC authentication not enabled');
    }
    try {
        const publicOrigin = getPublicOrigin(req);
        const client = await getOrInitOidcClient(publicOrigin);

        const codeVerifier = generators.codeVerifier();
        const codeChallenge = generators.codeChallenge(codeVerifier);
        const state = generators.state();

        // Constrain the post-login redirect to our own origin. An attacker-controlled
        // redirect= param would otherwise turn this endpoint into an open redirector
        // after a successful login.
        let originalUri = '/';
        const redirectParam = typeof req.query.redirect === 'string' ? req.query.redirect : '';
        if (redirectParam) {
            try {
                const parsed = new URL(redirectParam, publicOrigin);
                if (parsed.origin === publicOrigin) {
                    originalUri = parsed.pathname + parsed.search + parsed.hash;
                }
            } catch {
                originalUri = '/';
            }
        }

        pendingOidcFlows.set(state, { codeVerifier, originalUri, createdAt: Date.now() });

        const authUrl = client.authorizationUrl({
            redirect_uri: chosenRedirect(req),
            scope: 'openid profile email groups',
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        });
        console.log(`[Auth Service] OIDC login: state=${state.substring(0, 8)}... target=${originalUri}`);
        res.redirect(authUrl);
    } catch (err) {
        console.error('[Auth Service] OIDC login failed:', err);
        res.status(500).send('OIDC login failed: ' + err.message);
    }
});

// Exchange authorization code for tokens and mint a session cookie
app.get('/nhl-auth/oidc/callback', async (req, res) => {
    if (!OIDC_ENABLED) {
        return res.status(404).send('OIDC authentication not enabled');
    }
    try {
        const publicOrigin = getPublicOrigin(req);
        const client = await getOrInitOidcClient(publicOrigin);

        const params = client.callbackParams(req);
        if (!params.state || !pendingOidcFlows.has(params.state)) {
            console.warn(`[Auth Service] OIDC callback rejected: unknown state=${params.state}`);
            return res.status(400).send('Invalid or expired OIDC state');
        }
        const flow = pendingOidcFlows.get(params.state);
        pendingOidcFlows.delete(params.state);

        // The IdP redirected back to the same host the login used, so recomputing
        // from the callback request yields the matching redirect_uri (required to
        // equal the one sent at /authorize for the token exchange).
        const tokenSet = await client.callback(
            chosenRedirect(req),
            params,
            { state: params.state, code_verifier: flow.codeVerifier },
        );
        const claims = tokenSet.claims();

        const sessionId = generateSessionId();
        sessions[sessionId] = {
            expires: Date.now() + SESSION_DURATION_MS,
            oidcSub: claims.sub,
        };
        console.log(`[Auth Service] OIDC session created for sub=${claims.sub} (${sessionId.substring(0, 8)}...)`);

        res.cookie('appshield_session', sessionId, {
            httpOnly: true,
            secure: false,
            maxAge: SESSION_DURATION_MS,
            sameSite: 'lax',
        });
        res.redirect(flow.originalUri || '/');
    } catch (err) {
        console.error('[Auth Service] OIDC callback failed:', err);
        res.status(500).send('OIDC callback failed: ' + err.message);
    }
});

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        activeSessions: Object.keys(sessions).length,
        sessionDurationHours: SESSION_DURATION_HOURS
    });
});

// Start server
app.listen(PORT, () => {
    console.log('=====================================');
    console.log('[Auth Service] Started successfully');
    console.log(`[Auth Service] Listening on port ${PORT}`);
    console.log(`[Auth Service] Username configured: ${USERNAME ? 'Yes' : 'No'}`);
    console.log(`[Auth Service] Password configured: ${PASSWORD ? 'Yes' : 'No'}`);
    console.log(`[Auth Service] OIDC enabled: ${OIDC_ENABLED ? `Yes (registrar=${OIDC_REGISTRAR_URL})` : 'No'}`);
    console.log(`[Auth Service] Session duration: ${SESSION_DURATION_HOURS} hours`);
    console.log('=====================================');
});
