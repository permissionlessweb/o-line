FROM nginx:alpine

# certbot-nginx handles HTTP-01 ACME challenges and rewrites nginx.conf to add TLS.
# gettext provides envsubst for runtime config templating.
RUN apk add --no-cache certbot certbot-nginx gettext

COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

CMD ["/entrypoint.sh"]
