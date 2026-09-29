#!/bin/bash
set -e

# Password must be provided via env var
if [ -z "$JUMPHOST_PASSWORD" ]; then
    echo "ERROR: JUMPHOST_PASSWORD env var not set"
    exit 1
fi

# Set labuser password
echo "labuser:${JUMPHOST_PASSWORD}" | chpasswd

# Generate SSH host keys if missing
ssh-keygen -A

# Ensure sshd config allows password auth (for labuser) and key auth.
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
# Show /etc/motd on login
sed -i 's/^#\?PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config

# ── Authorized keys (master → jumphost passwordless access) ─────────
# The master's dnlab-multinode pubkey is injected via env var so root on
# the master can `ssh labuser@<jumphost>` without a password while the
# human-facing password login still works from the master shell.
if [ -n "${JUMPHOST_AUTHORIZED_KEYS:-}" ]; then
    mkdir -p /home/labuser/.ssh
    chmod 700 /home/labuser/.ssh
    printf '%s\n' "$JUMPHOST_AUTHORIZED_KEYS" > /home/labuser/.ssh/authorized_keys
    chmod 600 /home/labuser/.ssh/authorized_keys
    chown -R labuser:labuser /home/labuser/.ssh
    echo "Installed authorized_keys for labuser"
fi

# ── Login banner (list of VDs in this lab) ──────────────────────────
# JUMPHOST_VD_LIST is a space-separated list of logical VD names.
# JUMPHOST_VD_MAP is a space-separated logical=runtime map. Persist it because
# sshd login sessions do not inherit the container entrypoint environment.
# JUMPHOST_RELAY_MAP is a space-separated runtime-container=host:port:key map.
# JUMPHOST_LAB_NAME is the lab name itself.
: > /etc/dnlab-vds
if [ -n "${JUMPHOST_RELAY_MAP:-}" ]; then
    read -r -a relays <<< "$JUMPHOST_RELAY_MAP"
    for item in "${relays[@]}"; do
        echo "$item"
    done > /etc/dnlab-relays
else
    : > /etc/dnlab-relays
fi
chown root:labuser /etc/dnlab-relays
chmod 640 /etc/dnlab-relays
if [ -n "${JUMPHOST_VD_LIST:-}" ]; then
    read -r -a vds <<< "$JUMPHOST_VD_LIST"
    if [ -n "${JUMPHOST_VD_MAP:-}" ]; then
        read -r -a mappings <<< "$JUMPHOST_VD_MAP"
        for item in "${mappings[@]}"; do
            echo "$item"
        done > /etc/dnlab-vds
    else
        for vd in "${vds[@]}"; do
            echo "$vd"
        done > /etc/dnlab-vds
    fi

    {
        echo
        echo "======================================================"
        echo "  Lab: ${JUMPHOST_LAB_NAME:-unknown}"
        echo "  Virtual Devices in this lab:"
        for vd in "${vds[@]}"; do
            echo "    - $vd"
        done
        echo
        echo "  Commands:"
        echo "    vd list             → list virtual devices"
        echo "    vd connect <name>   → open console"
        echo "    vd log <name>       → show container log history"
        echo "    vd log -f <name>    → follow container log in real time"
        echo "    vd help             → show command help"
        echo "======================================================"
        echo
    } > /etc/motd
    # On Debian both `pam_motd.so motd=/run/motd.dynamic` and `pam_motd.so
    # noupdate` run at session open — the second one also prints /etc/motd,
    # which combined with sshd's `PrintMotd yes` produces the banner twice.
    # Comment out every pam_motd.so line so sshd alone prints /etc/motd.
    if [ -f /etc/pam.d/sshd ]; then
        sed -i '/pam_motd\.so/ s|^|#|' /etc/pam.d/sshd || true
    fi
fi

# Start reservation-only DHCPv4/RA/DHCPv6 when provided by the controller.
# eth1 is manually attached just after Docker starts this container. DHCP must
# not hold up (or terminate) SSH while that attach settles.
if [ -f /etc/dnsmasq.d/dnlab-mgmt.conf ]; then
    (
        for _ in {1..150}; do
            ip link show eth1 >/dev/null 2>&1 && break
            sleep 0.1
        done
        if ! ip link show eth1 >/dev/null 2>&1; then
            echo "ERROR: mgmt eth1 missing; DHCP service was not started" >&2
            exit 0
        fi
        if ! dnsmasq --conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf; then
            echo "ERROR: dnsmasq failed to start on mgmt eth1" >&2
        fi
    ) &
fi

# ── Routing / NAT ─────────────────────────────
# Il container deve essere istanziato con --sysctl net.ipv4.ip_forward=1
# per abilitare il forwarding del traffico

# NAT LAN → WAN
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Forwarding LAN → WAN
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

# Allow return traffic
iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "Jump host ready. Login: ssh labuser@<host-ip>"

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
