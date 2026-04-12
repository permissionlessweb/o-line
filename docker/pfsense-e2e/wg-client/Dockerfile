FROM alpine:3.19

RUN apk add --no-cache \
        openssh-server \
        wireguard-tools \
        curl \
        bash \
        iproute2 && \
    ssh-keygen -A && \
    mkdir -p /run/sshd /etc/wireguard

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
