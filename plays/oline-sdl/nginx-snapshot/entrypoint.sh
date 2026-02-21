#!/bin/sh
set -e

# Substitute SNAPSHOT_DOWNLOAD_DOMAIN and MINIO_BACKEND into the nginx config.
envsubst '${SNAPSHOT_DOWNLOAD_DOMAIN} ${MINIO_BACKEND}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf

# Start nginx temporarily so certbot can serve the HTTP-01 ACME challenge.
nginx

# Obtain/renew a Let's Encrypt certificate for the snapshot download domain.
# Uses certbot --nginx which will also update nginx.conf to enable TLS on 443.
# Falls back gracefully (|| true) if DNS isn't propagated yet on first boot.
certbot --nginx \
    -d "${SNAPSHOT_DOWNLOAD_DOMAIN}" \
    --non-interactive \
    --agree-tos \
    --email "${CERTBOT_EMAIL}" \
    || true

# Stop the temporary nginx.
nginx -s stop

# Run nginx in the foreground with the (possibly TLS-enabled) config.
exec nginx -g 'daemon off;'
