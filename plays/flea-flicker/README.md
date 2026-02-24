# Flea Flicker: Reverse Proxy

A reverse proxy is a service that sits between a client and a origin server as an intermediary to cache, encrypt, and forward requests and responses. Pick your flavor:

## [Caddy](https://caddyserver.com/)

## [Nginx](https://nginx.org/)

## Common Knowledge

### SSL Certificates

## FAQ

### When Do I Need To Setup Reverse Proxies?

Reverse proxies can provide a configurable layer that can enhance a nodes security, performance, and reliability (it can also do the opposite if not configured correctly).
Some keypoints for reverse proxies include:

- SSL/TLS Termination: Specific wallets and webapps require HTTPS connections, which requires the use of SSL/TLS certificates. Reverse proxies can
- Performance & Effeciency
- Load Balancing & Scalability
- Port & Permission Management
- Simplified Architechture

### How Do I Generate A SSL/TLS Certificate & Key?

There are many ways to do this. For oline, we employ & demonstrate the use of a pre-existing wildcard certificate, giving tls support to all `*.terp.network` sub-domains. There are a number of CA (certificate authorities), such as:

- cloudflare
- letsencrypt
- zerossh
- others (dyor!)

## RESEARCH

- reverse proxy blog: <https://medium.com/intrinsic-blog/why-should-i-use-a-reverse-proxy-if-node-js-is-production-ready-5a079408b2ca>
- ssl certs: <https://www.cloudflare.com/learning/ssl/what-is-an-ssl-certificate/>
