#!/usr/bin/env python3
"""Persistent, fixed-port FLiNOS launcher for dNLab/Containerlab.

The base VM provides one management NIC (tap0 <-> eth0).  This launcher adds
exactly eight data NICs (tap1..tap8 <-> eth1..eth8), matching the catalog.
The recipe patches vrnetlab's overlay path to /persist/overlay.qcow2.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import vrnetlab


_MAC_ADDRESS = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def containerlab_mac(index: int) -> str | None:
    """Return Containerlab's runtime MAC address for ``eth<index>``."""
    interface = f"eth{index}"
    try:
        mac = Path(f"/sys/class/net/{interface}/address").read_text(
            encoding="utf-8"
        ).strip().lower()
    except OSError:
        return None
    if not _MAC_ADDRESS.fullmatch(mac):
        raise RuntimeError(f"invalid Containerlab MAC for {interface}: {mac!r}")
    return mac


def management_mac() -> str:
    """Return the MAC identity assigned by dNLab to the guest management NIC."""
    configured = os.environ.get("CLAB_MGMT_MAC", "").strip().lower()
    if configured:
        if not _MAC_ADDRESS.fullmatch(configured):
            raise RuntimeError(f"invalid CLAB_MGMT_MAC: {configured!r}")
        return configured

    mac = containerlab_mac(0)
    if mac is None:
        raise RuntimeError("Containerlab management interface eth0 is required")
    return mac


class FlinosVM(vrnetlab.VM):
    def __init__(self) -> None:
        super().__init__(
            username="flinos",
            password="flinos",
            disk_image="/opt/flinos/flinos.qcow2",
            ram=int(os.environ.get("QEMU_MEMORY", "2048")),
            smp=os.environ.get("QEMU_SMP", "2"),
            min_dp_nics=8,
        )
        self.nic_type = "virtio-net-pci"
        self.num_nics = 8
        self.conn_mode = "tc"

    def gen_mgmt(self) -> list[str]:
        self.create_tc_tap_ifup()
        mac = management_mac()
        return [
            "-device", f"virtio-net-pci,netdev=p00,id=mgmt,mac={mac}",
            "-netdev", "tap,id=p00,ifname=tap0,script=/etc/tc-tap-ifup,downscript=no",
        ]

    def gen_nics(self) -> list[str]:
        self.nic_provision_delay()
        self.create_tc_tap_ifup()
        args: list[str] = []
        for index in range(1, 9):
            netdev = f"p{index:02d}"
            mac = containerlab_mac(index)
            args.extend([
                "-device",
                f"virtio-net-pci,netdev={netdev},id={netdev},mac={mac or vrnetlab.gen_mac(index)},bus=pci.1,addr=0x{index + 1:x}",
                "-netdev",
            ])
            if mac is not None:
                args.append(f"tap,id={netdev},ifname=tap{index},script=/etc/tc-tap-ifup,downscript=no")
            else:
                args.append(f"socket,id={netdev},listen=:{10000 + index}")
        return args

    def gen_dummy_nics(self) -> list[str]:
        # gen_nics already allocates all eight PCI slots with dummy backends.
        return []

    def bootstrap_spin(self) -> None:
        # VM.start() opens this socket while it verifies the serial console.
        # FLiNOS does not need a bootstrap conversation, but QEMU's telnet
        # serial backend accepts only one client.  Release the probe before
        # declaring the VM ready so the runtime relay can attach the GUI
        # console.
        if self.tn is not None:
            self.tn.close()
            self.tn = None
        self.running = True


class FlinosVR(vrnetlab.VR):
    def __init__(self) -> None:
        super().__init__("flinos", "flinos")
        self.vms = [FlinosVM()]


if __name__ == "__main__":
    vrnetlab.boot_delay()
    FlinosVR().start()
