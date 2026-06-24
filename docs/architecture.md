# Architecture: Nginx Hash Lock + Yundera Authelia OIDC

This document describes how `nginx-hash-lock` integrates with Yundera's Authelia instance to provide zero-config OIDC authentication for apps installed on a PCS. It covers the static container layout, the data flow for a first-time user hit, and the trust boundaries the design relies on.

## Components

| Component | Repo | Role | Network exposure |
|---|---|---|---|
| **mesh-router-caddy** | mesh-router-root | Edge TLS termination, subdomain → container routing via labels | Public (`:80`, `:443`) |
| **authelia** | — (upstream image `authelia/authelia:4.39`) | OIDC provider, user login, session management | Public via `auth-${DOMAIN}` (Caddy-routed) |
| **auth-registrar** | mesh-router-root/mesh-router-auth | Auto-registers OIDC clients for apps; derives `client_id` from caller's container name via PTR | **Internal only** (`pcs` network, `:9092`) |
| **nginx-hash-lock** (this repo) | Nginx-hash-lock | Per-app authentication sidecar. Terminates OIDC flow, manages session cookies, proxies to the real backend | Public via `<app>-<user>.${DOMAIN}` (Caddy-routed) |
| **app backend** | *(each app)* | The actual service being protected (ttyd, Jellyfin, etc.) | Internal (reached only via hash-lock) |

All of the above share the Docker `pcs` network. The app's backend container should have a name different from the hash-lock sidecar — the mesh-router routes `<container_name>-<user>.${DOMAIN}` to the container literally named `<container_name>`, so the sidecar must claim that name for subdomain routing to work.

## Static architecture

```mermaid
flowchart TB
    Browser[User's browser]

    subgraph PcsHost["PCS host"]
        direction TB

        subgraph PcsNet["Docker network: pcs"]
            direction TB

            Caddy["<b>mesh-router-caddy</b><br/>TLS termination<br/>:80, :443"]

            subgraph IdP["Authelia stack (template-root)"]
                direction LR
                Authelia["<b>authelia</b><br/>OIDC provider<br/>:9091"]
                Registrar["<b>auth-registrar</b><br/>client registration<br/>:9092 (internal only)"]
            end

            subgraph AppStack["App stack (per-app compose)"]
                direction LR
                HashLock["<b>nginx-hash-lock</b><br/>container: <i>myapp</i><br/>nginx :80 + auth-service :9999"]
                Backend["<b>app backend</b><br/>container: <i>myapp-backend</i>"]
            end
        end

        subgraph HostFs["Host filesystem"]
            Scripts[("/DATA/AppData/casaos/apps/yundera<br/>scripts + configuration.yml.tmpl")]
            AuthData[("/DATA/AppData/yundera/auth<br/>clients.d/, secrets/, users_database.yml")]
            Sock[("/var/run/docker.sock")]
        end
    end

    Browser -- "HTTPS<br/>myapp-alice.nsl.sh" --> Caddy
    Browser -- "HTTPS<br/>auth-alice.nsl.sh" --> Caddy
    Caddy -- "reverse_proxy" --> HashLock
    Caddy -- "reverse_proxy" --> Authelia
    HashLock -- "proxy_pass (internal)" --> Backend

    Registrar -. "rw" .-> AuthData
    Registrar -. "ro" .-> Scripts
    Registrar -. "docker run authelia crypto hash" .-> Sock
    Authelia -. "reads rendered config" .-> AuthData

    classDef pub fill:#e1f5ff,stroke:#0366d6
    classDef internal fill:#fff4e1,stroke:#b36200
    classDef file fill:#f6f8fa,stroke:#6a737d,stroke-dasharray: 3 3
    class Caddy,Authelia,HashLock pub
    class Registrar,Backend internal
    class Scripts,AuthData,Sock file
```

**Key point:** `auth-registrar` is the only service that touches both the host Docker socket and `authelia`'s config files — it's a concentrated-trust component. Every other hash-lock sidecar stays unprivileged.

## Data flow: first user hit on a protected path

This is the only non-trivial flow. Subsequent requests in the same session are a straight `auth_request → 200 → proxy_pass` with no round-trips to Authelia or the registrar.

```mermaid
sequenceDiagram
    autonumber
    participant U as Browser
    participant N as nginx (hash-lock)
    participant A as auth-service :9999
    participant R as auth-registrar :9092
    participant Z as authelia

    U->>N: GET https://myapp-alice.nsl.sh/
    N->>A: auth_request /internal-auth-check
    A-->>N: 401 (no cookie)
    N-->>U: 302 → /nhl-auth/oidc/login?redirect=/

    rect rgb(255, 244, 225)
        Note over U,R: Registration (once per hash-lock container lifetime)
        U->>N: GET /nhl-auth/oidc/login
        N->>A: proxy_pass
        A->>R: POST /register {redirect_uris}
        Note over R: PTR lookup on caller IP<br/>→ container_name = "myapp"<br/>client_id derived, not accepted
        R->>R: register-oidc-client.sh myapp ...<br/>(writes clients.d/myapp.yml,<br/>HUPs authelia)
        R-->>A: {client_id, client_secret, issuer_url}
        A->>A: cache OIDC client in memory<br/>+ openid-client.Issuer.discover(issuer_url)
    end

    rect rgb(225, 245, 255)
        Note over U,Z: Authorization code + PKCE
        A-->>U: 302 → https://auth-alice.nsl.sh/authorize?<br/>client_id=myapp&code_challenge=...&state=...
        U->>Z: GET /authorize
        Z-->>U: Authelia login page
        U->>Z: POST credentials
        Z-->>U: 302 → /nhl-auth/oidc/callback?code=...&state=...
        U->>N: GET /nhl-auth/oidc/callback
        N->>A: proxy_pass
        A->>Z: POST /token (code + code_verifier)
        Z-->>A: {id_token, access_token}
        A->>A: create session with oidcSub = claims.sub<br/>Set-Cookie: appshield_session
        A-->>U: 302 → / (original URL)
    end

    rect rgb(232, 255, 232)
        Note over U,N: All subsequent requests
        U->>N: GET / (with cookie)
        N->>A: auth_request /internal-auth-check
        A-->>N: 200 (oidcSub matches)
        N->>N: proxy_pass to backend
    end
```

### What's cached where

| State | Location | Lifetime |
|---|---|---|
| OIDC client (`{client_id, client_secret}`) | `clients.d/myapp.yml` + `clients.d/myapp.secret` on host | Persists across restarts. Idempotent re-registration returns the same secret. |
| OIDC client instance (`openid-client.Client`) | `auth-service` in-memory | Cleared on container restart. First login after restart triggers re-registration (no-op on the script side, just a fetch round-trip). |
| Session cookie | `auth-service` in-memory `sessions` dict | Cleared on container restart. Browser gets a fresh redirect-to-login on next request. |
| Authelia session | Authelia-side cookie on `auth-${DOMAIN}` | Independent of app sessions. Drives Authelia SSO — re-entering an OIDC flow from a second app within the Authelia session inactivity window skips the login prompt. |

## Trust boundaries

1. **Public edge** — Caddy handles TLS and routes by subdomain. Anything inside `pcs` trusts that `X-Forwarded-Host` came from Caddy; if Caddy is ever bypassed, the redirect URI validation downstream becomes the only defense.
2. **pcs network, public services** — Authelia and every hash-lock sidecar. Mutually reachable. An app-level RCE can reach them, so they assume hostile peers on the network (hence the PTR-based attestation on the registrar rather than "trust any caller on pcs").
3. **pcs network, private services** — `auth-registrar` and app backends. Not Caddy-labelled; not reachable from outside pcs. Backends are additionally firewalled behind their hash-lock sidecar at the routing layer (Caddy only labels the sidecar's container name, not the backend's).
4. **Host** — the `auth-registrar` container mounts the Docker socket and `/DATA/AppData/yundera/auth`. This is the concentrated-risk surface: one audited container can invoke `docker run` and write Authelia's config. Everything else stays unprivileged.

Redirect URI validation is the second line of defense if attestation is ever wrong: the registrar requires the first DNS label of every `redirect_uri` to equal the attested `client_id` or start with `client_id-`. See [mesh-router-auth/src/validation.ts](../../yundera-root/packages/mesh-router-root/mesh-router-auth/src/validation.ts) — the tests cover the typosquat cases (`myapp2.*` rejected).

## Integration checklist for a new app

To opt an app into OIDC auth:

1. Compose the app with a hash-lock sidecar whose `container_name` matches the app name (mesh-router routing constraint).
2. Attach the sidecar to the external `pcs` network so it can reach `auth-registrar`.
3. Set `OIDC_REGISTRAR_URL: "http://auth-registrar:9092"` on the sidecar. That single env var enables OIDC — no other secrets to inject, the sidecar self-registers.

See the "OIDC via Yundera Authelia" example in [../README.md](../README.md) for a complete compose snippet.

## Known limitations

- **OIDC mode currently supersedes** hash and credentials modes. Mixing (e.g. "hash-param for dashboard quick-access, OIDC for real users") is on the roadmap but not implemented.
- **Redirect URI updates** are not handled by the underlying `register-oidc-client.sh` script — an app that changes its canonical hostname requires manual cleanup of `clients.d/<id>.{yml,secret}` before the next registration. Tracked for a `--force` patch in template-root.
- **Session persistence** is in-memory. A restart of the hash-lock container logs everyone out of that app; Authelia's own session is unaffected, so re-login is transparent as long as the Authelia session is still valid.
- **Container name is the OIDC client id**, which means re-deploying an app under a different container name creates an orphan OIDC client entry. De-registration on uninstall is a nice-to-have not yet wired up.
