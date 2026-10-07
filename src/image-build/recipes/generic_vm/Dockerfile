FROM debian:trixie-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates git inetutils-telnet iproute2 python3 python3-zombie-telnetlib \
    qemu-system-x86 qemu-utils ovmf socat \
    && rm -rf /var/lib/apt/lists/*
RUN git init /opt/vrnetlab \
    && git -C /opt/vrnetlab remote add origin https://github.com/srl-labs/vrnetlab.git \
    && git -C /opt/vrnetlab fetch --depth 1 origin 3e8578d2e946d38a3176480e80f8510bdb2ee53a \
    && git -C /opt/vrnetlab checkout --detach FETCH_HEAD
COPY patch_vrnetlab.py /usr/local/bin/patch-vrnetlab.py
RUN python3 /usr/local/bin/patch-vrnetlab.py /opt/vrnetlab/common/vrnetlab.py
COPY disk.qcow2 /opt/generic/disk.qcow2
COPY spec.json launch.py entrypoint.sh /opt/generic/
# Debian bookworm ships OVMF_CODE.fd while trixie uses the 4M pair.
RUN chmod +x /opt/generic/entrypoint.sh \
    && for suffix in _4M '' ; do \
         code="/usr/share/OVMF/OVMF_CODE${suffix}.fd" ; \
         vars="/usr/share/OVMF/OVMF_VARS${suffix}.fd" ; \
         if [ -f "$code" ] && [ -f "$vars" ]; then \
           cp "$code" /opt/generic/OVMF_CODE.fd ; \
           cp "$vars" /opt/generic/OVMF_VARS.fd ; \
           break ; \
         fi ; \
       done \
    && test -s /opt/generic/OVMF_CODE.fd -a -s /opt/generic/OVMF_VARS.fd
EXPOSE 5000
WORKDIR /opt/generic
ENTRYPOINT ["/opt/generic/entrypoint.sh"]
