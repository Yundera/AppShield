# AppShield

A lightweight NGINX-based authentication proxy that protects web applications using **hash-based authentication** and **username/password authentication**.

## What It Does

AppShield sits in front of your application and provides flexible authentication options:

1. **Hash Authentication**: Block requests unless they include `?hash=YOUR_SECRET_HASH`
2. **Username/Password Authentication**: Show a login page requiring credentials
3. **Both Methods**: Accept either hash parameter OR valid login session
4. **No Authentication**: Optionally disable security entirely

## Quick Start

### Environment Variables

**Core Settings:**
```yaml
environment:
  BACKEND_HOST: "your-app"               # Required: Backend service hostname
  BACKEND_PORT: "8080"                   # Required: Backend service port
  LISTEN_PORT: "80"                      # Required: Port NGINX listens on (80 recommended for clean subdomains)
```

**Authentication Options:**
```yaml
  # Hash authentication — MACHINE / API access (CasaOS provides this value).
  # The secret can be presented three ways: ?hash=<value> in the URL, an
  # "Authorization: Bearer <value>" header, or HTTP Basic ("-u any:<value>").
  AUTH_HASH: $AUTH_HASH                  # Optional: enables machine/API auth (CasaOS provides this)
                                         # Important: Also add /?hash=$AUTH_HASH to x-casaos.index

  # How AUTH_HASH is sourced — AUTH_HASH_MODE: managed | env | off (default: off)
  #   off      No hash-based machine auth; any incoming AUTH_HASH is ignored. (default)
  #   env      Use AUTH_HASH from the environment as-is. The caller owns the value
  #            and its lifecycle — e.g. interpolated from a persistent .env so it
  #            survives uninstall/reinstall (see the Beacon app for the pattern).
  #   managed  AppShield owns the token: it generates a 128-hex secret once into
  #            AUTH_HASH_FILE (default /data/auth_hash) on a persistent volume and
  #            reuses it on every restart/reinstall. Immune to platform-side
  #            rotation. The incoming AUTH_HASH env is never read. Mount a volume
  #            at /data and surface the token via the app itself — a managed token
  #            is NOT shown through CasaOS tips.
  AUTH_HASH_MODE: "off"                  # Optional: source/lifecycle of AUTH_HASH
  AUTH_HASH_FILE: "/data/auth_hash"      # Optional: managed-mode token path (default shown)

  # Username/Password authentication
  USER: "admin"                          # Optional: Username for login page
  PASSWORD: "your-secure-password"       # Optional: Password for login page
  SESSION_DURATION_HOURS: "720"          # Optional: Session duration in hours (default: 720 = 30 days)
  SESSIONS_FILE: "/data/sessions.json"   # Optional: session persistence path (default shown). Mount a
                                         # volume at /data so sessions survive container recreates;
                                         # without one they only survive `docker restart`. Applies to
                                         # every auth mode (password, hash, OIDC).

  # OIDC authentication (registrar-driven SSO)
  OIDC_REGISTRAR_URL: "http://auth-registrar:9092"  # Setting this enables OIDC mode. The sidecar
                                                     # self-registers with the registrar at first
                                                     # login, gets back client_id + client_secret +
                                                     # issuer_url, and runs authorization_code + PKCE.
                                                     # No per-app secrets to configure.
                                                     # Must be reachable on the pcs network.

```

> **Removed in 2.0.8: `CREDENTIAL_VALIDATE_URL` / `CREDENTIAL_CACHE_TTL_SECONDS`.** These
> delegated an `Authorization` header to an external validator (the CasaOS bridge's
> `/validate`) so API clients could present real CasaOS credentials. The bridge is being
> retired, so the mechanism went with it. A gate that still sets the variable logs a warning
> and ignores it — and refuses to start if it was the only authentication configured, rather
> than silently serving unprotected. Use `OAUTH_RESOURCE`, or `AUTH_HASH` with
> `AUTH_HASH_MODE=env|managed`, for non-interactive access.

  # Identity propagation — tell the backend WHO got in (see "Identity propagation")
  IDENTITY_HEADERS: "off"                # Optional: DEFAULT IS ON. Set to off to stop forwarding the
                                         # user's identity (Remote-User & co) to the backend.
  IDENTITY_ASSERTION_SECRET: "<secret>"  # Optional: also emit X-AppShield-Assertion, a signed JWT of
                                         # same claims. Required for any backend that other containers
                                         # on the network can reach directly.
  IDENTITY_ASSERTION_TTL_SECONDS: "60"   # Optional: assertion lifetime (default shown, minimum 5)

  # Authorization — restrict WHICH authenticated identities may enter
  OIDC_REQUIRED_GROUPS: "admins"         # Optional: comma-separated. An interactive OIDC identity must
                                         # be in at least one. Empty (default) = any identity the IdP
                                         # authenticates gets in. Does not apply to machine auth.

**Bypass Options:**
```yaml
  ALLOWED_EXTENSIONS: "js,css,png,ico"   # Optional: Allow static files without auth
  ALLOWED_PATHS: "login,api/health"      # Optional: Allow specific paths without auth
  ALLOW_HASH_CONTENT_PATHS: "true"       # Optional: Allow /[40-hex-char]/* paths without auth (for Stremio, etc.)
```

**Proxy Behavior (Advanced):**
```yaml
  # These have sensible defaults - only override if needed
  PROXY_BUFFERING: "off"                 # Default: off. Use "on" for caching/rate-limiting support
  PROXY_REQUEST_BUFFERING: "off"         # Default: off. Use "on" if backend needs full body before processing
  PROXY_CONNECT_TIMEOUT: "300s"          # Default: 300s. Time to establish backend connection
  PROXY_SEND_TIMEOUT: "300s"             # Default: 300s. Timeout between write operations to backend
  PROXY_READ_TIMEOUT: "300s"             # Default: 300s. Timeout between read operations from backend
  CLIENT_MAX_BODY_SIZE: "0"              # Default: 0 (unlimited). Use "10G" or "100M" to limit uploads
```

## Authentication Modes

AppShield separates **two audiences**, configured independently:

- **Humans** pick **one** interactive method (strict either/or): **Web login** (a
  `USER`/`PASSWORD` form) **or** **SSO** (OIDC redirect to the PCS identity provider).
  They are mutually exclusive — if `OIDC_REGISTRAR_URL` is set, it wins.
- **Machines / API clients** use the **hash** (`AUTH_HASH`) — a non-interactive secret,
  and an *addition*: set it alongside either human method (or on its own) and it composes.

The three distinct mechanisms:

| Mechanism | Audience | How the client presents it | Interactive? |
|-----------|----------|----------------------------|--------------|
| **Hash** | Machine / API | `?hash=<secret>` URL param **or** `Authorization: Bearer <secret>` **or** HTTP Basic (`-u any:<secret>`) | No |
| **Web login** | Human | username/password form → session cookie | Yes |
| **SSO (OIDC)** | Human | redirect to the identity provider (Dex → its connector), authorization_code + PKCE → session cookie | Yes |

> **Hash = "true" HTTP Basic auth for machines.** In machine-only deployments the gate
> answers an unauthenticated request with `401 WWW-Authenticate: Basic`, so standard tooling
> (`curl -u`, HTTP client libraries) authenticates out of the box. The hash is the credential —
> it is checked against `AUTH_HASH`, never `USER`/`PASSWORD`.

> **Machine access beyond the hash.** For OAuth 2.1 Bearer tokens on a specific path
> (MCP endpoints and similar), see `OAUTH_RESOURCE` — that path is gated independently of
> the mode table below. Delegating credentials to an external validator
> (`CREDENTIAL_VALIDATE_URL`) was removed in 2.0.8; see the note above.

The mode is selected automatically from which variables are set:

| OIDC_REGISTRAR_URL | AUTH_HASH | USER/PASSWORD | Mode | Behavior |
|--------------------|-----------|---------------|------|----------|
| ✅ Set  | *(any)* | *(any)* | **OIDC** | Self-registers with the PCS's identity provider, runs authorization_code+PKCE, drops a session cookie |
| ❌      | ✅ Defined | ❌ Undefined | **Hash Only** | Machine/API: `?hash=`, Bearer, or HTTP Basic. `401 WWW-Authenticate: Basic` on failure |
| ❌      | ❌ Undefined | ✅ Defined | **Credentials Only** | Show login page, require username/password, no hash option |
| ❌      | ✅ Defined | ✅ Defined | **Both Methods** | Machine hash (`?hash=` / Bearer / Basic) **or** human web login |
| ❌      | ❌ Undefined | ❌ Undefined | **No Authentication** | Allow all requests (security disabled) |

> **OIDC + hash compose.** Set `OIDC_REGISTRAR_URL` **and** `AUTH_HASH` together to serve
> both audiences from one gate: interactive users get the SSO redirect, while non-interactive
> API / non-human clients pass `?hash=YOUR_SECRET_HASH` and bypass the redirect. The auth
> service honours a valid hash in any mode. (Static `USER`/`PASSWORD` credential mode does
> **not** compose with OIDC — use hash for machine access alongside OIDC.)

## Identity propagation

AppShield forwards the authenticated identity to the backend, using the header names the
forward-auth ecosystem already settled on. An off-the-shelf app that supports
"authentication by trusted proxy" therefore works behind the gate with no patch, and our own
apps get one contract to read.

**On by default.** Set `IDENTITY_HEADERS: "off"` for an app that must not receive the user's
email/name/groups, or one that mishandles these headers.

| Header(s) | Value | Present for |
|---|---|---|
| `Remote-User`, `X-Forwarded-User`, `X-Auth-Request-User`, `X-Forwarded-Preferred-Username`, `X-Auth-Request-Preferred-Username` | `preferred_username` (falls back to email, then sub); `USER` in credentials mode | `oidc`, `password` |
| `Remote-Email`, `X-Forwarded-Email`, `X-Auth-Request-Email` | email claim | `oidc` |
| `Remote-Name` | display name | `oidc` |
| `Remote-Groups`, `X-Forwarded-Groups`, `X-Auth-Request-Groups` | comma-separated groups claim | `oidc` |
| `X-AppShield-Method` | `oidc` \| `password` \| `hash` \| `oauth` | every authenticated request |
| `X-AppShield-Sub` | IdP subject identifier | `oidc`, `oauth` |
| `X-AppShield-Assertion` | signed JWT of all of the above | when `IDENTITY_ASSERTION_SECRET` is set |

The `Remote-*` set is Authelia's and Traefik's; the `X-Forwarded-*` / `X-Auth-Request-*`
aliases are oauth2-proxy's. They all carry the same values, so an app can read whichever
family it already supports. Only the three facts that have **no** convention — which
mechanism authenticated the caller, the IdP subject, and our signed assertion — use an
`X-AppShield-*` name.

**`X-AppShield-Method` is not decoration.** `hash` and `oauth` are non-interactive callers
with no person behind them; they get no `Remote-User`. An app that treats them as a user —
attributing actions to them, or granting them a user's permissions — is wrong.

**Values are raw UTF-8**, as the convention expects, with control characters stripped. Note
that HTTP header values are bytes: a receiver that decodes them as latin-1 (Node does, by
default) must re-decode as UTF-8 to render a name like `Alice Ré` correctly. Anything
needing exact fidelity should read the assertion instead.

**Empty means absent.** nginx drops a header whose value is empty, so a claim the IdP did
not assert simply does not arrive — never as an empty string.

### Trust model — read this before relying on the headers

Using the conventional names means real apps will act on them, which cuts both ways:

- **The gate always wins over the client.** On every proxied path — authenticated, bypassed
  via `ALLOWED_PATHS`/`ALLOWED_EXTENSIONS`, hash-content, OAuth resource — nginx overwrites
  the entire set: with the gate's values where there is an identity, with nothing where
  there isn't. A client that sends `Remote-User: admin` never has it reach the backend. This
  holds with `IDENTITY_HEADERS` on **or** off, and is the reason the off switch is not a
  security control.
- **The gate does not win over the network.** If the backend is reachable by anything other
  than its gate — and on a shared docker network like `pcs`, every other app container is
  "anything other than the gate" — that peer can connect directly and send whatever headers
  it likes.

So: for an app whose backend is only routable through its gate (no caddy labels, no published
ports — the standard Yundera app shape), the plain headers are enough. For a privileged app,
set `IDENTITY_ASSERTION_SECRET` and have the backend **verify** `X-AppShield-Assertion`
instead of trusting the plain headers:

```
alg  HS256, signed with IDENTITY_ASSERTION_SECRET
iss  appshield
aud  APP_NAME
sub  the IdP subject (or username where there is no IdP)
exp  now + IDENTITY_ASSERTION_TTL_SECONDS (default 60s)
     plus method / user / email / name / groups
```

It is minted per request and deliberately short-lived: it transports the gate's answer for
*this* request. It is not a session token and must not be stored or replayed as one.

### Restricting who may enter

`OIDC_REQUIRED_GROUPS` turns the gate from authenticate-only into authorize-too: an
interactive OIDC identity must be in at least one of the listed groups. It is enforced
twice — at the callback, so a rejected user gets one clear 403 instead of a cookie they
cannot use, and on every subsequent check, so tightening the list also evicts sessions
that already exist.

An OIDC identity with no `groups` claim at all cannot satisfy a non-empty requirement.
That is intentional: an app that requires `admins` must not open up because a connector
forgot to send the claim.

Machine auth (`hash`, `oauth`) is exempt — it carries no groups, and gating it here would
silently cut off API access the moment an app adopted group enforcement. Use a separate
gate, or omit `AUTH_HASH`, if machines must be excluded too.

### Revoking sessions (control API)

A gate session is a bearer credential good for its whole TTL — 30 days by default — and
until now nothing outside the gate could end one early. That is fine for a media app and
wrong for a privileged one: deleting an account, resetting its password or removing its
admin rights must take effect on sessions **already in flight**, not just on the next login.

`POST /nhl-auth/sessions/revoke` does that. It is enabled exactly when
`IDENTITY_ASSERTION_SECRET` is set (a gate without that secret answers `501` and has no
control surface at all).

```
POST /nhl-auth/sessions/revoke
Authorization: Bearer <control token>
Content-Type: application/json

{"user": "alice"}      every session for that preferred_username
{"sub": "CgVhbGljZQ"}  every session for that IdP subject
{"all": true}          every session on this gate

{"user": "alice", "except": "<sessionId>"}   ... but spare these
→ 200 {"revoked": 2}
```

`except` (string or array) is for the self-service case: an operator resetting their **own**
password must end every session opened with the old password without logging themselves out
of the page they are doing it from. The backend receives the browser's `appshield_session`
cookie (nginx forwards it), so it can name the one session to keep.

`sub` and `user` can be combined (a session matching either is revoked — what you want when
an account was renamed and older sessions still carry the previous username). Revoking
something already gone is `{"revoked": 0}`, not an error. Deletions persist to
`SESSIONS_FILE`, so a revocation is not undone by a gate restart.

**The control token** is an HS256 JWT signed with `IDENTITY_ASSERTION_SECRET` — the same
secret the backend already needs in order to verify identity assertions, used in the other
direction, so there is no second secret to provision:

```
alg  HS256, signed with IDENTITY_ASSERTION_SECRET
iss  appshield-backend
aud  appshield-control      ← NOT the app name
sub  free-form caller label (logged)
iat  required
exp  required, and at most 300s after iat
```

**Why the audience is different from the identity assertion's.** Identity assertions carry
`aud: APP_NAME` and are handed to the backend on every single request — where they may well
end up in a log. If control tokens shared that audience, every one of those assertions would
double as a session-revocation credential. The split is what keeps a leaked assertion
useless here, and the ≤300s lifetime cap is what stops a control token from becoming a
standing credential.

Everything under `/nhl-auth/` is reachable from the internet, and nginx proxies this endpoint
from `127.0.0.1`, so network origin cannot be used as a check — the token is the whole
authorization. Treat `IDENTITY_ASSERTION_SECRET` accordingly.

### Signing out

`GET|POST /nhl-auth/logout` ends the gate session and clears the cookie. What happens next
depends on what the identity provider supports, and the difference is the whole story.

**When the OP advertises an `end_session_endpoint`** (OIDC RP-Initiated Logout 1.0), the
gate redirects the browser there with an `id_token_hint`, a `client_id`, and a
`post_logout_redirect_uri` pointing at `/nhl-auth/logged-out`. That ends the OP session
too — so the next sign-in genuinely asks for a credential instead of silently replaying
one. If the OP also supports **Back-Channel Logout 1.0**, it then notifies every *other*
app in the session, so one sign-out ends them all.

**When it does not**, the gate falls back to a terminal "Signed out" page and says plainly
that the IdP session outlives this one. It deliberately does not bounce to `/`: the OP
would silently re-authenticate and logout would look broken.

**When the session's ID token has outlived the OP's signing key**, the hint is left out. The
gate keeps the ID token from login for the whole session (30 days by default), while an OP
rotates its keys much more often — Dex every 6 hours, keeping each for about a day. An OP
accepts an *expired* hint, but refuses one it can no longer verify (Dex: `400 Invalid
id_token_hint`), which would strand the user on an error page with the OP session still
alive. So the gate checks the token against the OP's current keys first, and when it does
not verify it sends neither `id_token_hint` nor `post_logout_redirect_uri` (an OP only
honours the latter for a client the hint names). The OP then asks the user to confirm and
finishes on its own "logged out" page: one extra click and no return to the app, but the OP
session really ends. The gate logs `logout without id_token_hint` when this happens.

Either way this is **best effort**. No OIDC session, no discovered client, an OP without a
logout endpoint, or a failure reaching it all fall through to the terminal page — failing
to reach the OP must never trap a user inside an app whose session was already destroyed.

Upstream is **not** propagated: signing out here does not sign you out of the IdP *behind*
the OP (e.g. a cloud account federated through Dex), the same way signing out of Keycloak
does not sign you out of Google. That is the norm the specs state. A deployment that wants
it offers a separate, deliberate affordance — the Yundera admin app's `UPSTREAM_LOGOUT_URL`.

> **Version note.** Dex advertised no logout of any kind through v2.45.1 — no
> `end_session_endpoint`, no browser session, a connector re-run on every `/authorize`. RP-
> Initiated and Back-Channel Logout are merged upstream but unreleased, and only take effect
> with `DEX_SESSIONS_ENABLED=true`. Against a Dex without them this gate takes the fallback
> path above, which is exactly the old behaviour.

`GET` is supported so the route can be linked (`403.html` does, as the way out of a
wrong-account dead end). To keep that from becoming a cross-site force-logout, a request
carrying `Sec-Fetch-Site: cross-site` with a `Sec-Fetch-Dest` other than `document` is
refused with 403 — that is an `<img>`/`<script>` load, never a real sign-out. Same-site
requests are unaffected.

### Back-channel logout

`POST /nhl-auth/backchannel-logout` receives a signed logout token when *another* app ends
a session this gate took part in (OIDC Back-Channel Logout 1.0). This is what makes logout
reach every app: each gate holds its own host-only `appshield_session`, so without it,
signing out of one app leaves the rest open for the remainder of their 30 days.

The endpoint is deliberately **unauthenticated by network and by cookie** — everything
under `/nhl-auth/` is internet-reachable and nginx proxies it from `127.0.0.1`, so neither
tells us anything. The JWS signature over the OP's JWKS is the entire check, which is why
every validation is mandatory and a failure is a 400 rather than a quiet 200:

- signature verifies against the issuer's JWKS, with `iss` and `aud` (this `client_id`)
- the `http://schemas.openid.net/event/backchannel-logout` event is present
- `nonce` is **absent** — this is what stops an ID token, signed by the same key, from
  being replayed here as a logout token
- at least one of `sid` / `sub` is present

`sid` is preferred: it names one session at the OP, so a user signed in on a phone and a
laptop only loses the one they signed out of. `sub` is the fallback for an OP that issues
no `sid`, and ends all of that subject's sessions here.

A successful call returns `200` with an empty body and `Cache-Control: no-store`. Zero
matching sessions is still success — "no session here" is the state the OP asked for, and
reporting the count would leak whether a given user is signed in to this app.

Registration of both `post_logout_redirect_uris` and `backchannel_logout_uri` is handled by
the registrar: the gate sends only `post_logout_path` / `backchannel_logout_path`, and the
registrar supplies the hosts (the same contract as `callback_path`). A registrar that does
not understand them ignores them, and logout degrades to this gate only.

### Important for CasaOS Deployments

**`$AUTH_HASH` is automatically provided by CasaOS** - you don't need to manually configure it. However, you must:

1. **Include `$AUTH_HASH` in the environment** (CasaOS will populate it)
2. **Add `?hash=$AUTH_HASH` to the index** in x-casaos metadata

Example:
```yaml
environment:
  AUTH_HASH: $AUTH_HASH  # CasaOS provides this automatically

x-casaos:
  index: /?hash=$AUTH_HASH  # Important! Pass hash to URL
```

This ensures the Dashboard button automatically includes the authentication hash.

### Critical: Container Naming for Subdomain Routing

**The AppShield container MUST have the same name as the app.** The mesh-router routes subdomains based on container name matching the app name in `docker-compose.yml`.

**Correct Setup:**
```yaml
name: myapp                          # App name

services:
  myapp:                             # ← Service name matches app name
    image: ghcr.io/yundera/appshield:latest
    container_name: myapp            # ← Container name matches app name
    environment:
      BACKEND_HOST: "myapp-backend"  # ← Points to backend
      ...

  myapp-backend:                     # ← Backend has different name
    image: your-actual-app:latest
    container_name: myapp-backend

x-casaos:
  main: myapp                        # ← Main service is the nginx proxy
```

**Why this matters:**
- Subdomain `myapp-username.example.com` routes to container named `myapp`
- If the backend has the app name, traffic bypasses AppShield entirely
- The nginx proxy must "claim" the app name for proper routing

> **OIDC mode enforces this too.** When OIDC is enabled, AppShield self-registers
> with the registrar, which derives the caller's identity from its **container name**
> (Docker reverse-DNS on the network) and only authorizes redirect URIs whose hostname
> first label equals that name (or starts with `<name>-`). So the gate container must be
> named after the app's subdomain — e.g. for `myapp-username.example.com`, the AppShield
> container must be named `myapp`. A sidecar named `myapp-proxy` will be **rejected**
> (`redirect URI hostname ... must start with "myapp-proxy-"`). Setting `hostname:` alone
> is not enough; it's the **container name** that the registrar reads.

## Docker Compose Examples

### Example 1: Hash-Only Authentication (CasaOS)

```yaml
services:
  hashlock:
    image: ghcr.io/yundera/appshield:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # CasaOS provides this
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "80"
    expose:
      - 80
    depends_on:
      - myapp

  myapp:
    image: your-app:latest

x-casaos:
  main: hashlock
  index: /?hash=$AUTH_HASH             # IMPORTANT: Include hash in URL
  webui_port: 80
```

**CasaOS Dashboard button:** Automatically opens with authentication hash

### Example 2: Username/Password Only (CasaOS)

```yaml
services:
  hashlock:
    image: ghcr.io/yundera/appshield:latest
    environment:
      USER: $USER                      # Set in CasaOS or compose
      PASSWORD: $PASSWORD              # Set in CasaOS or compose
      SESSION_DURATION_HOURS: "168"    # 1 week
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "80"
    expose:
      - 80
    depends_on:
      - myapp

  myapp:
    image: your-app:latest

x-casaos:
  main: hashlock
  index: /                             # No hash needed - shows login page
  webui_port: 80
```

**CasaOS Dashboard button:** Opens login page → Enter credentials → 1-week session

### Example 3: Both Methods (Hash OR Login) - CasaOS

```yaml
services:
  hashlock:
    image: ghcr.io/yundera/appshield:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # Option 1: CasaOS hash
      USER: $USER                      # Option 2: Password auth
      PASSWORD: $PASSWORD
      SESSION_DURATION_HOURS: "720"    # 30 days
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "80"
    expose:
      - 80
    depends_on:
      - myapp

  myapp:
    image: your-app:latest

x-casaos:
  main: hashlock
  index: /?hash=$AUTH_HASH             # Dashboard uses hash (quick access)
  webui_port: 80
```

**CasaOS Dashboard button:** Opens with hash (quick access)
**Alternative:** Visit without hash → Login page → Enter credentials → 30-day session

### Example 4: OIDC (registrar-driven SSO, zero-config)

> In OIDC mode the gate container **must be named after the app's subdomain** (see
> [Container Naming](#critical-container-naming-for-subdomain-routing) above). Here the
> app is `myapp`, so the AppShield container is `myapp` and the real app is `myapp-backend`.

```yaml
services:
  myapp:
    image: ghcr.io/yundera/appshield:latest
    container_name: myapp            # ← must match the app subdomain (= OIDC identity)
    environment:
      OIDC_REGISTRAR_URL: "http://auth-registrar:9092"  # Presence enables OIDC mode
      BACKEND_HOST: "myapp-backend"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "80"
    expose:
      - 80
    networks:
      - pcs                            # Required: must be on the pcs network to reach the registrar
    depends_on:
      - myapp-backend

  myapp-backend:
    image: your-app:latest
    container_name: myapp-backend

networks:
  pcs:
    external: true
    name: pcs

x-casaos:
  main: myapp
  index: /
  webui_port: 80
```

**What happens at first user hit:**
1. User hits `https://myapp-alice.example.com/` → nginx runs `auth_request` → 401 (no cookie).
2. Nginx redirects to `/nhl-auth/oidc/login`, which POSTs to `$OIDC_REGISTRAR_URL/register` (e.g. `http://auth-registrar:9092/register`) with its callback **path**.
3. The registrar identifies the caller as container `myapp` via PTR on the pcs network, registers an OIDC client with the SSO provider, and returns `{client_id, client_secret, issuer_url, redirect_uris}`.
4. The sidecar adopts the returned `redirect_uris` as its public host set, initializes `openid-client`, kicks off authorization_code + PKCE (S256), and redirects the browser to the SSO provider's `/authorize`.
5. The user logs in with the SSO provider → bounced back to `/nhl-auth/oidc/callback` **on the host the login started from** → session cookie set → redirected to the original URL.

Subsequent boots: the registrar is idempotent — the same client and secret come back, so the OIDC client is reused.

### Who decides which hostnames are ours

The registrar does. AppShield sends only its callback *path* and uses the `redirect_uris` that come back.

This matters because the host set is a property of the deployment, not of the app. `REDIRECT_HOST_SUFFIXES` lets the sidecar guess `<app>-<suffix>`, but the PCS **root domain** breaks that rule: whichever app the root domain proxies to is also served at the bare suffix (`example.com`, not just `myapp-example.com`), and nothing an app knows about itself reveals that. An app computing its own list therefore has no registrable callback on the bare domain, so a login starting there gets bounced to `myapp-example.com` mid-flow — which users report as "SSO sent me to a different URL". Letting the registrar answer fixes it for every app at once, including store apps whose compose nobody templates.

`REDIRECT_HOST_SUFFIXES` is still honoured as the pre-registration guess, as the fallback when `/register` is unreachable, and as what gets sent to registrars older than mesh-auth 1.2.0 (which require `redirect_uris` and ignore `callback_path`). Both fields are sent, so the sidecar works against either.

Two things stay locally computed on purpose:

- **The canonical origin** (`<app>-<first suffix>`) is never re-derived from the registrar's list. With `OAUTH_RESOURCE` set it becomes the OAuth issuer, which is baked into already-issued tokens and into discovery documents remote clients cache — moving it would invalidate all of them.
- **Session cookies stay host-scoped.** Logging in on the bare domain and on `myapp-example.com` yields two independent sessions. That was already true across the nip.io/sslip.io hosts; this change stops the host from *switching* mid-login, it does not merge sessions across hosts.

### OIDC back-channel

The issuer the registrar returns is a public hostname, and must be: it is the `iss` of every token and where the browser is sent. But the gate also calls the issuer itself — discovery, the code→token exchange, the JWKS fetch — and from inside a deployment that hostname resolves to the outside: the calls leave the machine, cross the gateway/CDN and come back in, for traffic between two containers on one bridge.

When the registrar also returns `internal_issuer_url` (mesh-auth `INTERNAL_ISSUER_URL`, e.g. `http://dex:5556`), the gate sends every request for a URL under `issuer_url` to the same path under the internal address instead. Nothing else changes: the issuer string, the tokens' `iss`, and the authorization and end-session URLs the browser is redirected to all stay public.

There is nothing to configure on the gate. No field ⇒ today's behaviour. The startup line says which path is in use:

```
[oidc] registered with http://auth-registrar:9092 as client myapp (issuer https://auth-alice.example.com, back-channel via http://dex:5556)
```

An internal address that does not answer fails the login (502, retried on the next attempt) rather than falling back to the public path — a silent detour would hide exactly the problem this removes.

This replaces the deployment-side workaround of pinning the issuer hostname with `extra_hosts` and adding the proxy's CA through `SSL_CERT_DIR`: a gate on an `internal_issuer_url` needs neither, nor the CA mount.

## How It Works

### Hash Authentication Mode
1. **With correct hash**: `https://yourapp.example.com/?hash=my-secret-123` → Access granted
2. **Without hash**: Returns 403 Forbidden with custom error page

### Username/Password Mode
1. **First visit**: Shows login page
2. **Enter credentials**: Username and password validated (2-second delay on failure for anti-brute-force)
3. **Session created**: Secure cookie with configurable expiration (default: 30 days)
4. **Subsequent visits**: Automatic access with valid session cookie

### Both Methods Mode
1. **With hash parameter**: Instant access (no login required)
2. **With valid session**: Access granted
3. **Without either**: Redirected to login page

## Optional Features

### Allow Static Assets (No Hash Required)

Useful for CSS, JavaScript, images:

```yaml
ALLOWED_EXTENSIONS: "js,css,png,ico,svg,woff,woff2"
```

Now `/styles/app.css` works without a hash, but `/admin` still requires it.

### Allow Public Paths (No Hash Required)

Useful for login pages or public APIs:

```yaml
ALLOWED_PATHS: "login,about,api/health,api/public"
```

Now `/login` and `/api/health` work without a hash, but `/dashboard` still requires it.

**Important - Reserved Paths:**
- `/nhl-auth/` is reserved for internal authentication endpoints and cannot be used in ALLOWED_PATHS
- `/login` is reserved for the login page
- All other paths are available for use in ALLOWED_PATHS
- The `/auth` path is now available for your application (previously reserved)

## Hash Content Paths (For Stremio and Media Servers)

Some applications like Stremio use 40-character hexadecimal paths for content:
- `/8187fed409fc90636a87a44b706ade4865e83bc9/video.mp4`
- `/bca2d44dcd7655ecfdffe81659a569d3525f0195/0`

These paths are dynamically generated and the **hash itself acts as the access token**. To allow these paths without requiring additional authentication:

```yaml
environment:
  ALLOW_HASH_CONTENT_PATHS: "true"
```

### Security Model

- **Main site** (`/`, `/settings`, etc.) → Requires login or `?hash=AUTH_HASH`
- **Content paths** (`/[40-hex-chars]` or `/[40-hex-chars]/...`) → Accessible if you know the
  content hash. The hash must be a **whole path segment**: `/<40hex>deadbeef` is not a hash and
  stays gated. The exemption is granted on the *shape* of the path, not on whether the hash
  names content that exists — anyone who can invent a well-formed hash reaches the backend
  unauthenticated, so enable this only for backends where that is acceptable.

This is similar to how signed URLs work on cloud storage services - the hash IS the authentication for that specific content.

### Example: Stremio with Hash Content Paths

```yaml
services:
  stremio:
    image: ghcr.io/yundera/appshield:latest
    environment:
      AUTH_HASH: $AUTH_HASH
      USER: "admin"
      PASSWORD: "stremio"
      BACKEND_HOST: "stremiocommunity"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "80"
      ALLOW_HASH_CONTENT_PATHS: "true"  # Required for video streaming
    expose:
      - 80

  stremiocommunity:
    image: tsaridas/stremio-docker:latest
```

## Real-World Examples: Protected Terminal (CasaOS)

### Hash-Only Authentication (safe-terminal-app-appshield.yml)
Quick access via URL hash parameter - Dashboard button includes hash automatically:

```yaml
services:
  yunderaterminal:
    image: ghcr.io/yundera/appshield:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # CasaOS provides this
      BACKEND_HOST: "ttyd"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "80"
    expose:
      - 80
    depends_on:
      - ttyd

  ttyd:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "chroot", "/host", "bash"]

x-casaos:
  main: yunderaterminal
  index: /?hash=$AUTH_HASH             # IMPORTANT: Pass hash to URL
  webui_port: 80
```

**CasaOS Dashboard:** Automatically opens with hash → Instant access

### Password Authentication (safe-terminal-app-nginxhashpass.yml)
Session-based login with username/password:

```yaml
services:
  yunderaterminalpass:
    image: ghcr.io/yundera/appshield:latest
    environment:
      USER: $USER                      # Set in CasaOS
      PASSWORD: $PASSWORD              # Set in CasaOS
      SESSION_DURATION_HOURS: "720"    # 30 days
      BACKEND_HOST: "ttydpass"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "80"
    expose:
      - 80
    depends_on:
      - ttydpass

  ttydpass:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "chroot", "/host", "bash"]

x-casaos:
  main: yunderaterminalpass
  index: /                             # No hash - show login page
  webui_port: 80
```

**CasaOS Dashboard:** Opens login page → Enter credentials → 30-day session

### Dual Authentication (safe-terminal-app-nginxhashboth.yml)
Accept BOTH hash OR password for maximum flexibility:

```yaml
services:
  yunderaterminalboth:
    image: ghcr.io/yundera/appshield:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # Option 1: CasaOS hash (Dashboard)
      USER: $USER                      # Option 2: Login page
      PASSWORD: $PASSWORD
      SESSION_DURATION_HOURS: "168"    # 1 week
      BACKEND_HOST: "ttydboth"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "80"
    expose:
      - 80
    depends_on:
      - ttydboth

  ttydboth:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "chroot", "/host", "bash"]

x-casaos:
  main: yunderaterminalboth
  index: /?hash=$AUTH_HASH             # Dashboard uses hash for quick access
  webui_port: 80
```

**CasaOS Dashboard:** Opens with hash → Instant access
**Alternative:** Visit without hash parameter → Login page → 1-week session

## Security Features

### Username/Password Authentication
- **Session-based authentication**: Secure httpOnly cookies prevent XSS attacks
- **Anti-brute-force protection**: 2-second delay on failed login attempts
- **Configurable session duration**: Set `SESSION_DURATION_HOURS` to control session lifetime
- **Automatic session cleanup**: Expired sessions are automatically removed from memory

### Hash Authentication
- **URL parameter validation**: Simple and effective for trusted environments
- **No server-side state**: Stateless authentication

## Security Notes

- **Hash is visible in URLs**: This is simple authentication, not encryption. Use HTTPS in production.
- **Use HTTPS in production**: Prevents hash and cookie exposure over network
- **Strong passwords**: Use strong passwords for username/password authentication
- **Session security**: Sessions are stored in memory and cleared on container restart
- **Rotate credentials**: Change `AUTH_HASH` or `PASSWORD` if compromised
- **Not a replacement for OAuth/SAML**: Use for simple cases or as an additional protection layer

## Files

### Core Files
- `Dockerfile` - Debian NGINX container with Node.js
- `nginx.conf` - NGINX configuration template with auth_request support
- `entrypoint.sh` - Configures authentication mode and starts services
- `403.html` - Custom error page for hash authentication failures
- `login.html` - Login page for username/password authentication

### Authentication Service
- `auth-service/app.js` - Express.js authentication service
- `auth-service/package.json` - Node.js dependencies

## Configuration Details

The entrypoint script automatically:
1. Determines authentication mode based on environment variables
2. Starts the Node.js auth service if credentials are configured
3. Configures hash content paths bypass if `ALLOW_HASH_CONTENT_PATHS=true`
4. Generates appropriate NGINX configuration for the selected auth mode
5. Configures optional allowed paths/extensions
6. Starts NGINX with the generated configuration

No manual configuration needed - just set environment variables and run.

### Services Started Based on Configuration

| Configuration | Auth Service (port 9999) | NGINX |
|--------------|--------------------------|-------|
| Hash only | ✅ | ✅ |
| Credentials only | ✅ | ✅ |
| Both methods | ✅ | ✅ |
| No authentication | ❌ | ✅ |

## Technical Architecture

### Authentication Flow

**Hash-Only Mode:**
```
Request → NGINX auth_request to auth service → Check session cookie
  ├─ Valid session → Backend
  └─ No/invalid session → Check ?hash parameter
      ├─ Valid hash → Create session cookie → Backend
      └─ Invalid/missing → Return 403 Forbidden
```

**Credentials-Only Mode:**
```
Request → NGINX auth_request to auth service → Check session cookie
  ├─ Valid session → Backend
  └─ No/invalid session → Redirect to /login → Validate credentials → Set cookie → Backend
```

**Both Methods Mode:**
```
Request → NGINX auth_request to auth service → Check session cookie
  ├─ Valid session → Backend
  └─ No/invalid session → Check ?hash parameter
      ├─ Valid hash → Backend
      └─ Invalid/missing → Redirect to /login
```

**OIDC Mode:**
```
Request → NGINX auth_request to auth service → Check session cookie
  ├─ Valid session (has oidcSub) → Backend
  └─ No/invalid session → Redirect to /nhl-auth/oidc/login
      ├─ First call: POST to auth-registrar → cache client creds in memory
      └─ Redirect to SSO provider /authorize (PKCE S256)
          → SSO login → /nhl-auth/oidc/callback
          → Exchange code for tokens → Mint session with oidcSub → Backend
```

**Hash Content Paths Mode (when ALLOW_HASH_CONTENT_PATHS=true):**
```
Request matching /[40-hex-chars]/* pattern → Direct proxy to backend (no auth)
Other requests → Normal authentication flow
```

### Session cookie

`appshield_session` is `HttpOnly`, `SameSite=Lax`, and `Secure` **when the request arrived
over HTTPS** (derived from `X-Forwarded-Proto`, which Caddy sets). It is not hardcoded
either way on purpose: always-off would let the cookie travel in plaintext on an HTTPS-only
host, and always-on would make a gate reached over plain HTTP set a cookie the browser
refuses to send back — an unbreakable login loop.

### Session Management
- Sessions stored in-memory (Node.js auth service)
- Automatic cleanup of expired sessions every hour
- Session IDs are cryptographically secure (32 random bytes)
- Sessions survive nginx reload but not container restart

## Application Compatibility

AppShield has been tested with:
- **Stremio** - Media streaming (use `ALLOW_HASH_CONTENT_PATHS=true`)
- **Jellyfin/Emby** - Media servers with transcoding
- **Plex** - Media server with remote access
- **qBittorrent** - Download manager
- **Transmission** - Torrent client
- **File browsers** - Filebrowser, FileShelter
- **Code servers** - VS Code Server, code-server
- **Terminal apps** - ttyd, wetty, gotty

The `ALLOW_HASH_CONTENT_PATHS` feature is useful for:
- Media servers that use 40-character hex paths for content
- Applications where the content hash acts as an access token
- Stremio and similar streaming applications

### Supported Features

| Feature | Status | Notes |
|---------|--------|-------|
| Standard HTTP/1.1 apps | ✅ | Fully supported |
| WebSocket connections | ✅ | Automatic detection and upgrade |
| Video/audio streaming | ✅ | Buffering disabled by default |
| Large file uploads | ✅ | Unlimited by default |
| Server-Sent Events (SSE) | ✅ | Proper headers configured |
| Long-polling requests | ✅ | 5-minute timeouts |
| REST APIs | ✅ | All methods supported |

### Known Limitations

| Feature | Status | Reason |
|---------|--------|--------|
| gRPC | ❌ | Requires `grpc_pass` directive and HTTP/2 - fundamentally different from HTTP proxying |
| HTTP/2 to backend | ❌ | Uses HTTP/1.1 for backend connections (sufficient for 99% of apps) |
| Headers with underscores | ⚠️ | Ignored by default (nginx default behavior) |

**Note on gRPC:** Applications using gRPC (some CI/CD tools, Kubernetes services) cannot be proxied through AppShield. gRPC requires a completely different nginx configuration using `grpc_pass` instead of `proxy_pass`.

## Proxy Behavior Configuration

AppShield is designed to work with **any application** out of the box. The defaults prioritize compatibility over performance.

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_BUFFERING` | `off` | Response buffering. `off` = streaming-friendly, `on` = better for caching |
| `PROXY_REQUEST_BUFFERING` | `off` | Request buffering. `off` = large uploads work, `on` = backend gets full body first |
| `PROXY_CONNECT_TIMEOUT` | `300s` | Time allowed to establish connection with backend |
| `PROXY_SEND_TIMEOUT` | `300s` | Timeout between successive write operations to backend |
| `PROXY_READ_TIMEOUT` | `300s` | Timeout between successive read operations from backend |
| `CLIENT_MAX_BODY_SIZE` | `0` | Maximum upload size. `0` = unlimited, or use `10G`, `100M`, etc. |

### When to Override Defaults

**Most apps need no configuration** - the defaults handle:
- Video/audio streaming (Stremio, Jellyfin, Plex)
- Large file uploads (ConvertX, file managers)
- WebSocket connections (terminals, real-time apps)
- Server-Sent Events (SSE)
- Long-polling requests

**Override only if:**

| Scenario | Setting |
|----------|---------|
| Need nginx-level caching | `PROXY_BUFFERING=on` |
| Need nginx rate-limiting | `PROXY_BUFFERING=on` |
| Backend requires full request before processing | `PROXY_REQUEST_BUFFERING=on` |
| Want to limit upload sizes | `CLIENT_MAX_BODY_SIZE=10G` |
| Very long operations (>5 min) | `PROXY_READ_TIMEOUT=3600s` |

### What's Fixed Automatically

These issues are handled without configuration:

| Feature | Implementation |
|---------|----------------|
| WebSocket support | Correct `Connection` header via nginx `map` directive |
| Forwarded headers | `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port` |
| SSE support | `X-Accel-Buffering: no` header |
| Backend redirects | Proper redirect rewriting |

## Building & Publishing

The Docker image is automatically built and published to GitHub Container Registry via GitHub Actions on every push to `main`.

**Image location:** `ghcr.io/yundera/appshield:latest`

For manual builds (development only):
```bash
docker build -t krizcold/appshield:dev .
docker push krizcold/appshield:dev
```
