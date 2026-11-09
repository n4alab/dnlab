FROM python:3.12-alpine

LABEL io.dnlab.runtime-relay.capabilities="lab-prefix-console-port-v1,multisession-console-v1,qualified-container-id-v1"

RUN apk add --no-cache docker-cli busybox-extras util-linux \
    && mkdir -p /usr/share/doc/dnlab/third-party \
    && printf '%s\n' \
        '# dNLab Third-Party Notices' \
        '' \
        'This image contains the dNLab runtime relay plus Python/Alpine packages and Docker CLI tooling.' \
        'Release builds must attach a generated SBOM and full notice bundle for the exact image tag.' \
        > /usr/share/doc/dnlab/third-party/THIRD_PARTY_NOTICES.md

COPY relay.py /usr/local/bin/dnlab-runtime-relay
RUN chmod +x /usr/local/bin/dnlab-runtime-relay

ENTRYPOINT ["/usr/local/bin/dnlab-runtime-relay"]
