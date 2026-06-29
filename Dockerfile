FROM nginx:latest

# Install Node.js and npm.
# Node 22 LTS is required by oidc-provider v9 (it uses URL.parse, added in Node
# 20.18/22) and Node 18 is EOL. The existing express/openid-client stack is
# fully compatible with Node 22.
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create required nginx cache directories
RUN mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp} && \
    chown -R nginx:nginx /var/cache/nginx && \
    chmod -R 755 /var/cache/nginx

# Force cache invalidation for configuration files
ARG CACHE_BUST=1
RUN echo "Build timestamp: $(date)" > /build-info

# Copy nginx configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY 403.html /usr/share/nginx/html/403.html
COPY login.html /usr/share/nginx/html/login.html

# Copy and install auth service
COPY auth-service /app/auth-service
WORKDIR /app/auth-service
RUN npm install --production

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /

ENTRYPOINT ["/entrypoint.sh"]

