FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        dnsmasq \
        bash-completion \
        iproute2 \
        iputils-ping \
        iputils-tracepath \
        tcpdump \
        curl \
        wget \
        vim \
        less \
        net-tools \
        dnsutils \
        netcat-openbsd \
        python3 \
        ca-certificates \
        iptables \
        telnet \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/sshd \
    && useradd -m -s /bin/bash labuser \
    && echo "labuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && mkdir -p /usr/share/doc/dnlab/third-party \
    && printf '%s\n' \
        '# dNLab Third-Party Notices' \
        '' \
        'This image contains the dNLab jumphost helper plus Debian packages such as OpenSSH, tcpdump and network tools.' \
        'Release builds must attach a generated SBOM and full notice bundle for the exact image tag.' \
        > /usr/share/doc/dnlab/third-party/THIRD_PARTY_NOTICES.md

COPY entrypoint.sh /entrypoint.sh
COPY vd /usr/local/bin/vd
COPY vd-relay-client /usr/local/bin/vd-relay-client
COPY vd-completion.bash /etc/bash_completion.d/vd
RUN chmod +x /entrypoint.sh /usr/local/bin/vd /usr/local/bin/vd-relay-client

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
