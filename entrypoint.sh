#!/bin/sh

echo "Starting AppShield..."

# On first run, save the original template
if [ ! -f /etc/nginx/nginx.conf.template ]; then
    echo "Saving original nginx.conf as template..."
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.template
fi

# Always start with a clean copy from template
echo "Copying clean template to working config..."
if ! cp /etc/nginx/nginx.conf.template /etc/nginx/nginx.conf; then
    echo "ERROR: Failed to copy template to working config"
    exit 1
fi

# Validate inputs before using in sed replacements
if ! echo "$BACKEND_HOST" | grep -qE '^[a-zA-Z0-9._-]+$'; then
    echo "ERROR: Invalid BACKEND_HOST (only alphanumeric, dots, underscores, and hyphens allowed)"
    exit 1
fi

if ! echo "$BACKEND_PORT" | grep -qE '^[0-9]+$' || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
    echo "ERROR: Invalid BACKEND_PORT (must be 1-65535)"
    exit 1
fi

if ! echo "$LISTEN_PORT" | grep -qE '^[0-9]+$' || [ "$LISTEN_PORT" -lt 1 ] || [ "$LISTEN_PORT" -gt 65535 ]; then
    echo "ERROR: Invalid LISTEN_PORT (must be 1-65535)"
    exit 1
fi

# Replace basic placeholders
sed -i "s/BACKEND_HOST_PLACEHOLDER/$BACKEND_HOST/g" /etc/nginx/nginx.conf
sed -i "s/BACKEND_PORT_PLACEHOLDER/$BACKEND_PORT/g" /etc/nginx/nginx.conf
sed -i "s/LISTEN_PORT_PLACEHOLDER/$LISTEN_PORT/g" /etc/nginx/nginx.conf

# These defaults prioritize compatibility over performance
PROXY_BUFFERING="${PROXY_BUFFERING:-off}"
PROXY_REQUEST_BUFFERING="${PROXY_REQUEST_BUFFERING:-off}"
PROXY_CONNECT_TIMEOUT="${PROXY_CONNECT_TIMEOUT:-300s}"
PROXY_SEND_TIMEOUT="${PROXY_SEND_TIMEOUT:-300s}"
PROXY_READ_TIMEOUT="${PROXY_READ_TIMEOUT:-300s}"
CLIENT_MAX_BODY_SIZE="${CLIENT_MAX_BODY_SIZE:-0}"

echo "========================================="
echo "Proxy Configuration:"
echo "  PROXY_BUFFERING: $PROXY_BUFFERING"
echo "  PROXY_REQUEST_BUFFERING: $PROXY_REQUEST_BUFFERING"
echo "  PROXY_CONNECT_TIMEOUT: $PROXY_CONNECT_TIMEOUT"
echo "  PROXY_SEND_TIMEOUT: $PROXY_SEND_TIMEOUT"
echo "  PROXY_READ_TIMEOUT: $PROXY_READ_TIMEOUT"
echo "  CLIENT_MAX_BODY_SIZE: $CLIENT_MAX_BODY_SIZE"
echo "========================================="

# Replace proxy behavior placeholders
sed -i "s/PROXY_BUFFERING_PLACEHOLDER/$PROXY_BUFFERING/g" /etc/nginx/nginx.conf
sed -i "s/PROXY_REQUEST_BUFFERING_PLACEHOLDER/$PROXY_REQUEST_BUFFERING/g" /etc/nginx/nginx.conf
sed -i "s/PROXY_CONNECT_TIMEOUT_PLACEHOLDER/$PROXY_CONNECT_TIMEOUT/g" /etc/nginx/nginx.conf
sed -i "s/PROXY_SEND_TIMEOUT_PLACEHOLDER/$PROXY_SEND_TIMEOUT/g" /etc/nginx/nginx.conf
sed -i "s/PROXY_READ_TIMEOUT_PLACEHOLDER/$PROXY_READ_TIMEOUT/g" /etc/nginx/nginx.conf
sed -i "s/CLIENT_MAX_BODY_SIZE_PLACEHOLDER/$CLIENT_MAX_BODY_SIZE/g" /etc/nginx/nginx.conf

# ---------------------------------------------------------------------------
# AUTH_HASH source selection — AUTH_HASH_MODE: managed | env | off (default off)
#
#   off      No hash-based machine auth. Any incoming AUTH_HASH is ignored.
#            This is the default: hash auth must be opted into explicitly.
#
#   env      Use AUTH_HASH from the environment as-is. The caller owns the
#            value and its lifecycle — e.g. interpolated from a persistent
#            .env so it survives uninstall/reinstall (see the Beacon app).
#
#   managed  AppShield owns the token: generate a 64-byte (128 hex) secret once
#            into AUTH_HASH_FILE on a persistent volume and reuse it on every
#            restart/reinstall. Never reads the incoming AUTH_HASH env, so it is
#            immune to platform-side rotation. NOTE: a managed token is not
#            surfaced through CasaOS tips — expose it via the app itself.
# ---------------------------------------------------------------------------
AUTH_HASH_MODE="${AUTH_HASH_MODE:-off}"
AUTH_HASH_FILE="${AUTH_HASH_FILE:-/data/auth_hash}"

case "$AUTH_HASH_MODE" in
    managed)
        if [ ! -f "$AUTH_HASH_FILE" ]; then
            mkdir -p "$(dirname "$AUTH_HASH_FILE")"
            od -An -tx1 -N64 /dev/urandom | tr -d ' \n' > "$AUTH_HASH_FILE"
            chmod 600 "$AUTH_HASH_FILE"
            echo "AUTH_HASH_MODE=managed: generated new persistent token at $AUTH_HASH_FILE"
        else
            echo "AUTH_HASH_MODE=managed: reusing persistent token at $AUTH_HASH_FILE"
        fi
        AUTH_HASH="$(cat "$AUTH_HASH_FILE")"
        ;;
    env)
        if [ -n "$AUTH_HASH" ]; then
            echo "AUTH_HASH_MODE=env: using AUTH_HASH from environment"
        else
            echo "AUTH_HASH_MODE=env: no AUTH_HASH in environment (machine/API auth disabled)"
        fi
        ;;
    off)
        if [ -n "$AUTH_HASH" ]; then
            echo "AUTH_HASH_MODE=off: ignoring AUTH_HASH from environment"
        fi
        AUTH_HASH=""
        ;;
    *)
        echo "ERROR: invalid AUTH_HASH_MODE '$AUTH_HASH_MODE' (expected: managed | env | off)"
        exit 1
        ;;
esac
# Export so the node auth-service child inherits the resolved value.
export AUTH_HASH

# Determine authentication mode
# OIDC handles interactive (human) logins. A static AUTH_HASH MAY be set alongside
# OIDC for non-interactive API / non-human access: the auth service honours a valid
# ?hash= in any mode, so API clients bypass the OIDC redirect while humans still get
# the SSO flow. (USER/PASSWORD credential mode does NOT compose with OIDC.)
# OIDC is considered enabled iff OIDC_REGISTRAR_URL is set (points at the registrar
# on the pcs network, typically http://auth-registrar:9092).
# Machine/API auth is enabled by a static AUTH_HASH and/or an external credential
# validator (CREDENTIAL_VALIDATE_URL — e.g. the CasaOS bridge, for real per-user
# API identity). Either one composes with the human methods exactly like a hash.
if [ -n "$AUTH_HASH" ] || [ -n "$CREDENTIAL_VALIDATE_URL" ]; then MACHINE_AUTH=1; else MACHINE_AUTH=0; fi

AUTH_MODE="none"
if [ -n "$OIDC_REGISTRAR_URL" ]; then
    AUTH_MODE="oidc_only"
elif [ "$MACHINE_AUTH" = "1" ] && [ -n "$USER" ] && [ -n "$PASSWORD" ]; then
    AUTH_MODE="both"
elif [ "$MACHINE_AUTH" = "1" ]; then
    AUTH_MODE="hash_only"
elif [ -n "$USER" ] && [ -n "$PASSWORD" ]; then
    AUTH_MODE="credentials_only"
fi

echo "========================================="
echo "Authentication Mode: $AUTH_MODE"
if [ "$AUTH_MODE" = "oidc_only" ] && [ "$MACHINE_AUTH" = "1" ]; then
    echo "  + machine/API bypass enabled (hash and/or CasaOS credentials via header)"
fi
echo "========================================="

# Start auth service if any authentication is configured (for session management).
# Also start it when the MCP OAuth broker is enabled, since the provider runs
# inside the auth-service node process.
if [ "$AUTH_MODE" = "hash_only" ] || [ "$AUTH_MODE" = "credentials_only" ] || [ "$AUTH_MODE" = "both" ] || [ "$AUTH_MODE" = "oidc_only" ] || [ -n "$MCP_OAUTH_RESOURCE" ]; then
    echo "Starting authentication service..."
    export SESSION_DURATION_HOURS="${SESSION_DURATION_HOURS:-720}"
    cd /app/auth-service
    node app.js > /var/log/auth-service.log 2>&1 &
    AUTH_SERVICE_PID=$!
    echo "Auth service started with PID: $AUTH_SERVICE_PID"
    cd /

    # Wait for auth service to be ready with timeout
    echo "Waiting for auth service to be ready..."
    TIMEOUT=10
    for i in $(seq 1 $TIMEOUT); do
        # Try curl first, fall back to nc (netcat) port check
        if command -v curl > /dev/null 2>&1; then
            if curl -sf --max-time 2 http://127.0.0.1:9999/health > /dev/null 2>&1; then
                echo "Auth service is ready"
                break
            fi
        elif command -v nc > /dev/null 2>&1; then
            if nc -z 127.0.0.1 9999 > /dev/null 2>&1; then
                echo "Auth service is ready (port check)"
                break
            fi
        else
            # No curl or nc available, just wait and trust the logs
            if [ $i -ge 3 ]; then
                echo "Auth service assumed ready (no health check tools available)"
                break
            fi
        fi

        if [ $i -eq $TIMEOUT ]; then
            echo "ERROR: Auth service failed to start within ${TIMEOUT}s"
            echo "Last 20 lines of auth service log:"
            tail -20 /var/log/auth-service.log
            exit 1
        fi
        sleep 1
    done
fi

# Build the authentication check block based on AUTH_MODE
AUTH_CHECK_BLOCK=""

case "$AUTH_MODE" in
    "none")
        echo "No authentication configured - allowing all requests"
        AUTH_CHECK_BLOCK="            # No authentication required"
        ;;

    "hash_only")
        echo "Machine/API authentication configured (hash via ?hash=, Authorization: Basic, or Bearer)"
        AUTH_CHECK_BLOCK="            # Machine/API auth: ?hash=, or AUTH_HASH via Authorization Basic/Bearer
            auth_request /internal-auth-check;
            auth_request_set \$auth_cookie \$upstream_http_set_cookie;
            add_header Set-Cookie \$auth_cookie;
            error_page 401 = @auth_failed_basic;"

        # Machine-only mode: on failure issue a true HTTP Basic challenge so clients
        # (curl -u, etc.) are prompted to authenticate. No human login page.
        sed -i 's|location / {|location @auth_failed_basic {\
            add_header WWW-Authenticate '\''Basic realm="AppShield"'\'' always;\
            return 401;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        ;;

    "credentials_only")
        echo "Credentials-only authentication configured"
        AUTH_CHECK_BLOCK="            # Credentials-only authentication
            auth_request /internal-auth-check;
            auth_request_set \$auth_cookie \$upstream_http_set_cookie;
            add_header Set-Cookie \$auth_cookie;
            error_page 401 = @auth_failed_login;"

        # Add named location for auth failure handling
        sed -i 's|location / {|location @auth_failed_login {\
            return 302 /login?redirect=$request_uri;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        ;;

    "both")
        echo "Both hash and credentials authentication configured"
        AUTH_CHECK_BLOCK="            # Auth service checks both hash and session
            auth_request /internal-auth-check;
            auth_request_set \$auth_cookie \$upstream_http_set_cookie;
            add_header Set-Cookie \$auth_cookie;
            error_page 401 = @auth_failed_login;"

        # Use same simple redirect as credentials_only
        # Auth service handles hash checking internally
        sed -i 's|location / {|location @auth_failed_login {\
            return 302 /login?redirect=$request_uri;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        ;;

    "oidc_only")
        echo "OIDC authentication configured (registrar=$OIDC_REGISTRAR_URL)"
        AUTH_CHECK_BLOCK="            # OIDC authentication — auth service validates the session cookie;
            # on 401 the browser is redirected to the auth service's /nhl-auth/oidc/login
            # endpoint, which kicks off the authorization_code flow against the SSO provider (Dex, via the registrar).
            auth_request /internal-auth-check;
            auth_request_set \$auth_cookie \$upstream_http_set_cookie;
            add_header Set-Cookie \$auth_cookie;
            error_page 401 = @auth_failed_oidc;"

        sed -i 's|location / {|location @auth_failed_oidc {\
            return 302 /nhl-auth/oidc/login?redirect=$request_uri;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        ;;
esac

# Prepare authentication block for insertion (deferred until after dynamic paths configuration)
AUTH_CHECK_ESCAPED=$(echo "$AUTH_CHECK_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g')

# Handle ALLOWED_EXTENSIONS
if [ -n "$ALLOWED_EXTENSIONS" ]; then
    echo "Configuring allowed extensions: $ALLOWED_EXTENSIONS"
    # Convert comma-separated to regex format: js,css,png -> (js|css|png)
    EXTENSIONS_REGEX=$(echo "$ALLOWED_EXTENSIONS" | sed 's/,/|/g')
    EXTENSIONS_REGEX="($EXTENSIONS_REGEX)"
    echo "Extensions regex: $EXTENSIONS_REGEX"
    # Escape forward slashes for sed (pipes and parentheses should NOT be escaped for nginx regex)
    EXTENSIONS_ESCAPED=$(echo "$EXTENSIONS_REGEX" | sed 's/\//\\\//g')
    sed -i "s/ALLOWED_EXTENSIONS_PLACEHOLDER/$EXTENSIONS_ESCAPED/g" /etc/nginx/nginx.conf
else
    echo "No allowed extensions configured - removing extensions block"
    # Remove the entire extensions location block if no extensions specified
    sed -i '/# Allow specific file extensions/,/^        }/d' /etc/nginx/nginx.conf
fi

# Handle ALLOWED_PATHS
if [ -n "$ALLOWED_PATHS" ]; then
    echo "Configuring allowed paths: $ALLOWED_PATHS"
    # Normalize paths: strip leading/trailing slashes and spaces from each comma-separated value
    # This handles: "/guild,/auth" -> "guild,auth"
    #              "login, /api/health/, /guild" -> "login,api/health,guild"
    #              "page/\",/something/else/" -> "page/\",something/else"
    NORMALIZED_PATHS=$(echo "$ALLOWED_PATHS" | \
        sed 's/^[ \/]\+//;s/[ \/]\+$//;s/[ \/]\+,/,/g;s/,[ \/]\+/,/g' | \
        sed 's/,\+/,/g')
    echo "Normalized paths: $NORMALIZED_PATHS"
    # Convert comma-separated to regex format: login,api/health -> (login|api/health)
    PATHS_REGEX=$(echo "$NORMALIZED_PATHS" | sed 's/,/|/g')
    PATHS_REGEX="($PATHS_REGEX)"
    echo "Paths regex: $PATHS_REGEX"
    # Escape only forward slashes for sed substitution (pipes and parentheses should NOT be escaped for nginx regex)
    PATHS_ESCAPED=$(echo "$PATHS_REGEX" | sed 's/\//\\\//g')
    sed -i "s/ALLOWED_PATHS_PLACEHOLDER/$PATHS_ESCAPED/g" /etc/nginx/nginx.conf
else
    echo "No allowed paths configured - removing paths block"
    # Remove the entire paths location block if no paths specified
    sed -i '/# Allow specific paths/,/^        }/d' /etc/nginx/nginx.conf
fi

# Handle ALLOW_HASH_CONTENT_PATHS (for Stremio and similar apps that use 40-char hex paths)
if [ "$ALLOW_HASH_CONTENT_PATHS" = "true" ] || [ "$ALLOW_HASH_CONTENT_PATHS" = "1" ]; then
    echo "Enabling hash content paths bypass (40-character hex paths)"

    # Create hash paths config file - allows paths like /bca2d44dcd7655ecfdffe81659a569d3525f0195/...
    cat > /tmp/hash_content_paths.conf <<EOF
        # Allow 40-character hex content paths without authentication
        # Used by Stremio and similar apps where the hash itself is the access token
        location ~ "^/[a-f0-9]{40}" {
            set \$backend_upstream "$BACKEND_HOST:$BACKEND_PORT";
            proxy_pass http://\$backend_upstream;
            proxy_http_version 1.1;

            # === Standard proxy headers ===
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Forwarded-Port \$server_port;

            # === WebSocket support (uses map for correct behavior) ===
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
        }
EOF

    # Insert the include directive before main location
    if ! grep -q "include /tmp/hash_content_paths.conf" /etc/nginx/nginx.conf; then
        sed -i '0,/# Main location - authentication logic/s//        include \/tmp\/hash_content_paths.conf;\n\n        &/' /etc/nginx/nginx.conf
    fi

    echo "Hash content paths enabled - paths matching /[a-f0-9]{40}* bypass authentication"
else
    echo "Hash content paths disabled (set ALLOW_HASH_CONTENT_PATHS=true to enable)"
fi

# Apply authentication block to nginx configuration
sed -i "s/AUTH_CHECK_BLOCK_PLACEHOLDER/$AUTH_CHECK_ESCAPED/" /etc/nginx/nginx.conf

# ---------------------------------------------------------------------------
# MCP OAuth 2.1 broker (opt-in via MCP_OAUTH_RESOURCE)
# When enabled, write an include file with the OAuth/MCP location blocks and
# splice it in via the MCP_OAUTH_BLOCK_PLACEHOLDER. When disabled, the
# placeholder is removed -> byte-identical nginx behaviour to before.
# ---------------------------------------------------------------------------
if [ -n "$MCP_OAUTH_RESOURCE" ]; then
    echo "MCP OAuth enabled (resource=$MCP_OAUTH_RESOURCE) — adding OAuth/MCP nginx routes"
    mkdir -p "${OAUTH_DATA_DIR:-/data/oauth}"

    cat > /tmp/mcp_oauth.conf <<EOF
        # === MCP OAuth 2.1 broker — auth-service (oidc-provider) on :9999 ===
        location = /.well-known/openid-configuration {
            proxy_pass http://127.0.0.1:9999;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-Proto \$redirect_scheme;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
        location = /.well-known/oauth-authorization-server {
            proxy_pass http://127.0.0.1:9999;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-Proto \$redirect_scheme;
            proxy_set_header X-Forwarded-Host \$host;
        }
        location = /.well-known/oauth-protected-resource {
            proxy_pass http://127.0.0.1:9999;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-Proto \$redirect_scheme;
        }
        # Provider protocol + interaction + admin page (admin self-gates in node)
        location ^~ /AppShield/ {
            proxy_pass http://127.0.0.1:9999;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-Proto \$redirect_scheme;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Cookie \$http_cookie;
        }
        # /mcp — gated by Bearer JWT / hash via auth_request. On a 401 from the
        # auth subrequest, nginx auto-propagates its WWW-Authenticate header to
        # the client (the RFC 9728 discovery challenge set by /nhl-auth/check),
        # so no human login redirect and no manual header re-emission is needed.
        location ^~ /mcp {
            auth_request /internal-auth-check;
            set \$backend_upstream "$BACKEND_HOST:$BACKEND_PORT";
            proxy_pass http://\$backend_upstream;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$redirect_scheme;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Forwarded-Port \$server_port;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
            proxy_set_header Authorization \$http_authorization;
        }
EOF

    sed -i 's|MCP_OAUTH_BLOCK_PLACEHOLDER|        include /tmp/mcp_oauth.conf;|' /etc/nginx/nginx.conf
else
    sed -i 's|MCP_OAUTH_BLOCK_PLACEHOLDER||' /etc/nginx/nginx.conf
fi

echo "========================================="
echo "Final nginx configuration:"
echo "========================================="
cat /etc/nginx/nginx.conf
echo "========================================="

# Wait for backend DNS to be resolvable before starting nginx
echo "Waiting for backend DNS resolution ($BACKEND_HOST)..."
DNS_TIMEOUT=30
for i in $(seq 1 $DNS_TIMEOUT); do
    if getent hosts "$BACKEND_HOST" > /dev/null 2>&1; then
        echo "Backend DNS resolved: $BACKEND_HOST -> $(getent hosts "$BACKEND_HOST" | awk '{print $1}')"
        break
    fi
    if [ $i -eq $DNS_TIMEOUT ]; then
        echo "WARNING: Backend DNS resolution timeout after ${DNS_TIMEOUT}s, starting anyway..."
    fi
    sleep 1
done

# Start nginx
echo "Starting nginx..."
exec nginx -g "daemon off;"

