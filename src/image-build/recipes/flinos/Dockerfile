# dNLab FLINOS image recipe. The srl-labs fork supplies Containerlab's tc
# datapath; launch.py creates the fixed 1 management + 8 data NIC topology.
FROM debian:trixie-slim

ARG VRNETLAB_REF=v0.20.1
ARG FLINOS_QCOW=flinos.qcow2

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates git inetutils-telnet iproute2 python3 python3-zombie-telnetlib \
    qemu-system-x86 qemu-utils socat \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${VRNETLAB_REF}" \
    https://github.com/srl-labs/vrnetlab.git /opt/vrnetlab

COPY patch_vrnetlab.py /usr/local/bin/patch-vrnetlab.py
RUN python3 /usr/local/bin/patch-vrnetlab.py /opt/vrnetlab/common/vrnetlab.py

COPY ${FLINOS_QCOW} /opt/flinos/flinos.qcow2
COPY launch.py /opt/flinos/launch.py
COPY launch.sh /opt/flinos/launch.sh
RUN chmod +x /opt/flinos/launch.sh

EXPOSE 5000
WORKDIR /opt/flinos
ENTRYPOINT ["/opt/flinos/launch.sh"]
