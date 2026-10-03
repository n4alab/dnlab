# dNLab FLINOS image recipe. The srl-labs fork supplies Containerlab's tc
# datapath; launch.py creates the fixed 1 management + 8 data NIC topology.
FROM debian:trixie-slim


RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates git inetutils-telnet iproute2 python3 python3-zombie-telnetlib \
    qemu-system-x86 qemu-utils socat \
    && rm -rf /var/lib/apt/lists/*
RUN git init /opt/vrnetlab \
    && git -C /opt/vrnetlab remote add origin https://github.com/srl-labs/vrnetlab.git \
    && git -C /opt/vrnetlab fetch --depth 1 origin 3e8578d2e946d38a3176480e80f8510bdb2ee53a \
    && git -C /opt/vrnetlab checkout --detach FETCH_HEAD \
    && test "$(git -C /opt/vrnetlab rev-parse HEAD)" = 3e8578d2e946d38a3176480e80f8510bdb2ee53a

COPY patch_vrnetlab.py /usr/local/bin/patch-vrnetlab.py
RUN python3 /usr/local/bin/patch-vrnetlab.py /opt/vrnetlab/common/vrnetlab.py

COPY flinos.qcow2 /opt/flinos/flinos.qcow2
COPY OVMF_CODE.fd OVMF_VARS.fd /opt/flinos/firmware/
COPY launch.py launch.sh /opt/flinos/
COPY entrypoint.sh /usr/local/bin/flinos-entrypoint
RUN chmod 0444 /opt/flinos/firmware/OVMF_CODE.fd \
    && chmod +x /opt/flinos/launch.sh /usr/local/bin/flinos-entrypoint

EXPOSE 5000
WORKDIR /opt/flinos
ENTRYPOINT ["/usr/local/bin/flinos-entrypoint"]
