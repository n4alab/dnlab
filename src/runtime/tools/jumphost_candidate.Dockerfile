# Isolated test candidate; use a locally qualified immutable base.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
LABEL io.dnlab.jumphost.capabilities="qualified-relay-inventory-v1"
COPY --chmod=0755 entrypoint.sh /entrypoint.sh
COPY --chmod=0644 inventory.py /usr/local/lib/dnlab-inventory.py
COPY --chmod=0755 vd /usr/local/bin/vd
COPY --chmod=0755 vd-relay-client /usr/local/bin/vd-relay-client
