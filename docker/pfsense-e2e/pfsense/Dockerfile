FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        iptables \
        iproute2 \
        procps \
        jq \
        sudo \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /etc/wireguard /usr/local/etc/wireguard \
    && chmod 700 /etc/wireguard /usr/local/etc/wireguard

COPY entrypoint.sh /entrypoint.sh
COPY server.py /server.py
COPY pfSsh.php /opt/mock/pfSsh.php
COPY easyrule /opt/mock/easyrule
COPY apply_firewall_rules.sh /opt/mock/apply_firewall_rules.sh
RUN chmod +x /entrypoint.sh /opt/mock/pfSsh.php /opt/mock/easyrule /opt/mock/apply_firewall_rules.sh

EXPOSE 22 8880

ENTRYPOINT ["/entrypoint.sh"]
