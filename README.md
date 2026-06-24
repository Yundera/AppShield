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

  # Username/Password authentication
  USER: "admin"                          # Optional: Username for login page
  PASSWORD: "your-secure-password"       # Optional: Password for login page
  SESSION_DURATION_HOURS: "720"          # Optional: Session duration in hours (default: 720 = 30 days)

  # OIDC authentication (registrar-driven SSO)
  OIDC_REGISTRAR_URL: "http://auth-registrar:9092"  # Setting this enables OIDC mode. The sidecar
                                                     # self-registers with the registrar at first
                                                     # login, gets back client_id + client_secret +
                                                     # issuer_url, and runs authorization_code + PKCE.
                                                     # No per-app secrets to configure.
                                                     # Must be reachable on the pcs network.

  # CasaOS-credential API auth (MACHINE, real per-user identity, no redirect)
  CREDENTIAL_VALIDATE_URL: ""             # When set, an "Authorization: Basic <user:pass>"
                                          # or "Bearer <token>" that isn't the static AUTH_HASH
                                          # is verified here — point it at the CasaOS bridge's
                                          # INTERNAL /validate port (http://casaos-oidc-bridge:8090/validate),
                                          # which checks it against CasaOS. Lets API clients use
                                          # `-u <casaos-user>:<casaos-pass>`. No browser redirect.
                                          # The validator is pcs-network-only, so no secret is needed.
  CREDENTIAL_CACHE_TTL_SECONDS: "60"      # Optional: cache successful validations (default 60s)
```

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
| **SSO (OIDC)** | Human | redirect to the identity provider (Dex → CasaOS), authorization_code + PKCE → session cookie | Yes |

> **Hash = "true" HTTP Basic auth for machines.** In machine-only deployments the gate
> answers an unauthenticated request with `401 WWW-Authenticate: Basic`, so standard tooling
> (`curl -u`, HTTP client libraries) authenticates out of the box. The hash is the credential —
> it is checked against `AUTH_HASH`, never `USER`/`PASSWORD`.

> **CasaOS identity over the API.** Set `CREDENTIAL_VALIDATE_URL` (→ the CasaOS bridge's
> `/validate`) so machine clients can authenticate with their **real CasaOS credentials** —
> `-u <casaos-user>:<casaos-pass>` (HTTP Basic) or a CasaOS `Bearer` token — instead of, or
> alongside, a shared `AUTH_HASH`. No browser redirect: the gate verifies the credential
> out-of-band via the bridge (which checks it against CasaOS), so an API call carries a real
> per-user identity. Successful checks are cached for `CREDENTIAL_CACHE_TTL_SECONDS`. This is
> a machine mechanism — humans still use Web login or SSO. (OIDC's password grant can't reach
> CasaOS through Dex, which is why this goes via the bridge, not Dex.)

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
2. Nginx redirects to `/nhl-auth/oidc/login`, which POSTs to `$OIDC_REGISTRAR_URL/register` (e.g. `http://auth-registrar:9092/register`) with its callback URL.
3. The registrar identifies the caller as container `myapp` via PTR on the pcs network, registers an OIDC client with the SSO provider, and returns `{client_id, client_secret, issuer_url}`.
4. The sidecar initializes `openid-client`, kicks off authorization_code + PKCE (S256), and redirects the browser to the SSO provider's `/authorize`.
5. The user logs in with the SSO provider → bounced back to `/nhl-auth/oidc/callback` → session cookie set → redirected to the original URL.

Subsequent boots: the registrar is idempotent — the same client and secret come back, so the OIDC client is reused.

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
- **Content paths** (`/[40-hex-chars]/*`) → Accessible if you know the content hash

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
