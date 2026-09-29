"""Cumulus VX legacy-launcher hardware, breakout, and readiness transform."""

from __future__ import annotations


MARKER = "# dnlab-patched: cumulus-breakout-readiness-v4"

_HELPERS = r'''
PORTS_CONF_FILE = "/config/ports.conf"
DNLAB_CONTROL_USER = "dnlab"
DNLAB_CONTROL_PASSWORD = "Dnlab123!"
PREALLOCATED_DATA_NICS = 64
VIRTIO_NET_VECTORS = 2
FIRST_EXTRA_SLOT = 33
LOGIN_TIMEOUT = 15
LOGIN_READY_TIMEOUT = 600
PLATFORM_READY_TIMEOUT = 300
BREAKOUT_TIMEOUT = 120
LOGOUT_TIMEOUT = 15
CONSOLE_POLL_TIMEOUT = 1.0
BREAKOUT_UPLOAD_FILE = "/tmp/dnlab-cumulus-breakout.b64"
BREAKOUT_RULES_FILE = "/etc/udev/rules.d/70-dnlab-cumulus-breakout.rules"
SERIAL_CHUNK_SIZE = 512


def _parse_breakout():
    if not os.path.isfile(PORTS_CONF_FILE):
        return 0, []
    with open(PORTS_CONF_FILE, encoding="utf-8") as ports_file:
        content = ports_file.read()
    entries = {
        int(match.group(1)): int(match.group(2))
        for match in re.finditer(r"(\d+)=(\d+)x", content)
    }
    if not entries:
        return 0, []
    max_port = max(entries)
    breakouts = sorted(
        (parent, lanes)
        for parent, lanes in entries.items()
        if lanes > 1
    )
    return max_port, breakouts


def _compute_renames(_max_port, breakouts):
    renames = []
    slot = FIRST_EXTRA_SLOT
    for parent, lanes in breakouts:
        for lane in range(lanes):
            renames.append((slot, f"swp{slot}", f"swp{parent}s{lane}"))
            slot += 1
    return renames
'''

_BOOTSTRAP = r'''    def bootstrap_spin(self):
        if self._bootstrap_done:
            if not self._breakout_done:
                if not self._write_udev_rules():
                    self._finish_startup("breakout interface reconciliation failed")
                    return
                self._breakout_done = True
                self._readiness_deadline = time.monotonic() + PLATFORM_READY_TIMEOUT
            if not self._platform_is_ready():
                if time.monotonic() >= self._readiness_deadline:
                    self._finish_startup(
                        "platform readiness timed out before switchd and nvued became active"
                    )
                return
            self._finish_startup()
            return

        if time.monotonic() >= self._login_deadline:
            self._finish_startup(
                f"login prompt was not detected within {LOGIN_READY_TIMEOUT} seconds"
            )
            return

        (_, match, res) = self._console_expect(
            [b"login: ", b"Login: ", b"cumulus login: ", b"Cumulus login: "],
            1,
        )
        if match:
            try:
                self._technical_login()
            except Exception as exc:
                self._finish_startup(f"technical login failed: {exc}")
                return
            self._bootstrap_done = True
            self._readiness_deadline = time.monotonic() + PLATFORM_READY_TIMEOUT
            return

        if res != b"":
            self.logger.trace("OUTPUT: %s", res.decode(errors="ignore"))
            self.spins = 0
        self.spins += 1

    def _console_read(self, timeout):
        transport = getattr(self.scrapli_tn, "transport", None)
        socket_wrapper = getattr(transport, "socket", None)
        raw_socket = getattr(socket_wrapper, "sock", None)
        if raw_socket is None:
            raise RuntimeError("serial console socket is not available")
        readable, _, _ = select.select([raw_socket], [], [], timeout)
        if not readable:
            return b""
        return self.tn.read_very_eager()

    def _console_expect(self, patterns, timeout):
        deadline = time.monotonic() + timeout
        received = b""
        while True:
            for index, pattern in enumerate(patterns):
                match = re.search(pattern, self._console_buffer)
                if match:
                    response = self._console_buffer
                    self._console_buffer = self._console_buffer[match.end():]
                    return index, match, response
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                response = self._console_buffer
                fragment_size = max(
                    (len(pattern) - 1 for pattern in patterns),
                    default=0,
                )
                self._console_buffer = response[-fragment_size:] if fragment_size else b""
                return -1, None, received
            data = self._console_read(min(CONSOLE_POLL_TIMEOUT, remaining))
            if data:
                self._console_buffer += data
                received += data

    def _console_read_until(self, expected, timeout):
        (_, _, response) = self._console_expect([re.escape(expected)], timeout)
        return response

    def _write_secret(self, value):
        self.tn.write(value.encode() + b"\r")

    def _technical_login(self):
        self.wait_write(DNLAB_CONTROL_USER, None)
        (_, password_prompt, _) = self._console_expect([b"Password:"], LOGIN_TIMEOUT)
        if not password_prompt:
            raise RuntimeError("password prompt not detected")
        self._write_secret(DNLAB_CONTROL_PASSWORD)
        (_, shell, response) = self._console_expect([rb"\$ ", b"# "], LOGIN_TIMEOUT)
        if not shell:
            raise RuntimeError(
                "control credentials rejected: "
                + response.decode(errors="replace")[-200:]
            )
        self.wait_write("printf '__DNLAB_LOGIN_OK__\\n'", None)
        result = self._console_read_until(b"__DNLAB_LOGIN_OK__", LOGIN_TIMEOUT)
        if b"__DNLAB_LOGIN_OK__" not in result:
            raise RuntimeError("control shell validation marker not received")

    def _platform_is_ready(self):
        try:
            self.wait_write(
                "printf '__DNLAB_switchd_%s__ __DNLAB_nvued_%s__\\n' "
                "$(systemctl is-active switchd 2>/dev/null) "
                "$(systemctl is-active nvued 2>/dev/null)",
                None,
            )
            (_, match, res) = self._console_expect(
                [rb"__DNLAB_switchd_active__ __DNLAB_nvued_active__"],
                5,
            )
        except Exception as exc:
            self.logger.debug("Platform readiness check failed: %s", exc)
            return False
        if match:
            return True
        self.logger.debug(
            "Platform not ready (console tail): %s",
            res.decode(errors="replace")[-300:],
        )
        return False

    def _write_udev_rules(self):
        targets = {
            slot: f"swp{slot}"
            for slot in range(FIRST_EXTRA_SLOT, PREALLOCATED_DATA_NICS + 1)
        }
        for slot, _natural, lane_name in self._breakout_renames:
            targets[slot] = lane_name

        rules = [
            "# Generated by dNLab for Cumulus VX breakout lanes.",
            f"# Flat swp1..swp{FIRST_EXTRA_SLOT - 1} ports remain independent "
            "of these aliases.",
        ]
        macs = {}
        for slot in targets:
            mac = self.get_intf_mac(f"{self.data_intf_prefix}{slot}")
            if not mac:
                self.logger.error("No MAC for Cumulus data slot eth%d", slot)
                return False
            macs[slot] = mac.lower()

        lane_slots = {
            slot for slot, _natural, _lane_name in self._breakout_renames
        }
        for slot in sorted(lane_slots):
            rules.append(
                f'SUBSYSTEM=="net", ACTION=="add", '
                f'ATTR{{address}}=="{macs[slot]}", NAME="{targets[slot]}"'
            )

        preflight_commands = []
        collision_commands = []
        change_commands = []
        stage_commands = []
        final_commands = []
        verify_commands = []
        for slot, target in targets.items():
            mac = macs[slot]
            current_var = f"current_{slot}"
            current_ref = "$" + "{" + current_var + "}"
            lookup = (
                "for address_file in /sys/class/net/*/address; do "
                f"[ \"$(tr '[:upper:]' '[:lower:]' < \"$address_file\")\" = '{mac}' ] "
                "|| continue; basename \"$(dirname \"$address_file\")\"; break; done"
            )
            preflight_commands.extend(
                [
                    f'{current_var}="$({lookup})"',
                    f'if [ -z "{current_ref}" ]; then '
                    f'fail preflight {slot} "guest interface for MAC {mac} not found"; fi',
                ]
            )
            collision_commands.append(
                f"if [ -e /sys/class/net/{target} ] && "
                f"[ \"$(tr '[:upper:]' '[:lower:]' < /sys/class/net/{target}/address)\" "
                f"!= '{mac}' ]; then fail collision {slot} "
                f'"target name {target} belongs to another interface"; fi'
            )
            change_commands.append(
                f'[ "{current_ref}" = "{target}" ] || needs_change=1'
            )
            stage_commands.append(
                f'if [ "{current_ref}" != "dnl{slot}" ]; then '
                f'ip link set dev "{current_ref}" down || '
                f'fail stage-down {slot} "unable to bring interface down"; '
                f'ip link set dev "{current_ref}" name "dnl{slot}" || '
                f'fail stage-rename {slot} "unable to assign temporary name"; fi'
            )
            final_commands.append(
                f'ip link set dev "dnl{slot}" name "{target}" || '
                f'fail final-rename {slot} "unable to assign {target}"'
            )
            verify_commands.append(
                f'if [ ! -e /sys/class/net/{target} ] || '
                f'! grep -Fxiq "{mac}" /sys/class/net/{target}/address; then '
                f'fail verify {slot} "{target} does not match its assigned MAC"; fi'
            )

        rules_b64 = base64.b64encode(("\n".join(rules) + "\n").encode()).decode()
        script = (
            f"rm -f {BREAKOUT_UPLOAD_FILE}\n"
            "set -u\n"
            "switchd_stopped=0\n"
            "failure_reported=0\n"
            "fail() {\n"
            "  rc=$?\n"
            "  failure_reported=1\n"
            "  printf '__DNLAB_BREAKOUT_ERROR__ phase=%s slot=%s rc=%s detail=%s\\n' "
            "\"$1\" \"$2\" \"$rc\" \"$3\"\n"
            "  exit 1\n"
            "}\n"
            "cleanup() {\n"
            "  rc=$?\n"
            "  if [ \"$switchd_stopped\" = 1 ]; then\n"
            "    systemctl start switchd >/dev/null 2>&1 || true\n"
            "  fi\n"
            "  if [ \"$rc\" -ne 0 ] && [ \"$failure_reported\" = 0 ]; then\n"
            "    printf '__DNLAB_BREAKOUT_ERROR__ phase=unexpected slot=na "
            "rc=%s detail=unexpected_failure\\n' \"$rc\"\n"
            "  fi\n"
            "}\n"
            "trap cleanup EXIT\n"
            + "\n".join(preflight_commands)
            + "\n"
            + "\n".join(collision_commands)
            + "\n"
            "needs_change=0\n"
            + "\n".join(change_commands)
            + "\n"
            f"desired_rules=$(mktemp {BREAKOUT_RULES_FILE}.XXXXXX) || "
            'fail rules-temp na "unable to create temporary rules file"\n'
            f"echo {rules_b64} | base64 -d > \"$desired_rules\" || "
            'fail rules-decode na "unable to decode rules"\n'
            f"cmp -s \"$desired_rules\" {BREAKOUT_RULES_FILE} || needs_change=1\n"
            "if [ \"$needs_change\" = 0 ]; then\n"
            "  rm -f \"$desired_rules\"\n"
            "  echo __DNLAB_BREAKOUT_OK__ changed=0\n"
            "  exit 0\n"
            "fi\n"
            'systemctl stop switchd || fail switchd-stop na "unable to stop switchd"\n'
            "switchd_stopped=1\n"
            + "\n".join(stage_commands)
            + "\n"
            f"install -o root -g root -m 0644 \"$desired_rules\" "
            f"{BREAKOUT_RULES_FILE} || "
            'fail rules-install na "unable to install rules"\n'
            "rm -f \"$desired_rules\"\n"
            + "\n".join(final_commands)
            + "\n"
            + "\n".join(verify_commands)
            + "\n"
            'systemctl start switchd || fail switchd-start na "unable to start switchd"\n'
            "switchd_stopped=0\n"
            "echo __DNLAB_BREAKOUT_OK__ changed=1\n"
        )
        script_b64 = base64.b64encode(script.encode()).decode()

        (_, shell, response) = self._console_expect(
            [rb"\$ ", b"# "], LOGIN_TIMEOUT
        )
        if not shell:
            self.logger.error(
                "Shell prompt not available before breakout upload: %s",
                response.decode(errors="replace")[-300:],
            )
            return False

        upload_commands = [f": > {BREAKOUT_UPLOAD_FILE}"]
        upload_commands.extend(
            f"printf %s {script_b64[offset:offset + SERIAL_CHUNK_SIZE]} "
            f">> {BREAKOUT_UPLOAD_FILE}"
            for offset in range(0, len(script_b64), SERIAL_CHUNK_SIZE)
        )
        for command in upload_commands:
            self.wait_write(command, None)
            (_, shell, response) = self._console_expect(
                [rb"\$ ", b"# "], LOGIN_TIMEOUT
            )
            if not shell:
                self.logger.error(
                    "Shell prompt not returned during breakout upload: %s",
                    response.decode(errors="replace")[-300:],
                )
                return False

        self.wait_write(
            f"sudo -n bash -c 'base64 -d {BREAKOUT_UPLOAD_FILE} | bash'",
            None,
        )
        (result_index, marker, result) = self._console_expect(
            [
                rb"__DNLAB_BREAKOUT_OK__ changed=[01](?:\r\n|\n|\r)",
                rb"__DNLAB_BREAKOUT_ERROR__[^\r\n]*(?:\r\n|\n|\r)",
                rb"\$ ",
                b"# ",
            ],
            BREAKOUT_TIMEOUT,
        )
        if marker and result_index in (0, 1):
            (_, shell, prompt_response) = self._console_expect(
                [rb"\$ ", b"# "], LOGIN_TIMEOUT
            )
            if not shell:
                self.logger.error(
                    "Shell prompt not returned after breakout result: %s",
                    (result + prompt_response).decode(errors="replace")[-500:],
                )
                return False
        if marker and result_index == 0:
            self.logger.info(
                "Cumulus breakout reconciliation completed: %s",
                marker.group(0).decode(errors="replace").strip(),
            )
            return True
        if marker and result_index == 1:
            self.logger.error(
                "Cumulus breakout reconciliation failed: %s",
                marker.group(0).decode(errors="replace").strip(),
            )
            return False
        if marker and result_index in (2, 3):
            self.logger.error(
                "Breakout command returned to the shell without a result marker: %s",
                result.decode(errors="replace")[-500:],
            )
            return False
        self.logger.error(
            "Breakout reconciliation timed out: %s",
            result.decode(errors="replace")[-500:],
        )
        return False

    def _logout_console(self):
        try:
            self.wait_write("logout", None)
            (_, match, res) = self._console_expect(
                [b"login: ", b"Login: ", b"cumulus login: ", b"Cumulus login: "],
                LOGOUT_TIMEOUT,
            )
        except Exception as exc:
            self.logger.warning("Console logout failed: %s", exc)
            return False
        if match:
            return True
        self.logger.warning(
            "Login prompt not detected after logout: %s",
            res.decode(errors="replace")[-300:],
        )
        return False

    def _finish_startup(self, degraded_reason=None):
        if self._bootstrap_done and not self._logout_console() and not degraded_reason:
            degraded_reason = "login prompt not detected after technical logout"
        if degraded_reason:
            self.degraded_reason = degraded_reason
            self.logger.warning("Cumulus startup degraded: %s", degraded_reason)
        if self.tn is not None:
            self.tn.close()
            self.tn = None
        startup_time = datetime.datetime.now() - self.start_time
        self.logger.info("Startup complete in: %s", startup_time)
        self.running = True
'''


def patch(text: str) -> tuple[str, bool]:
    hardware_defaults = '''DEFAULT_RAM_MB = 2048
DEFAULT_SMP = "2"
'''
    aligned_defaults = '''DEFAULT_RAM_MB = 4096
'''
    if hardware_defaults in text:
        text = text.replace(hardware_defaults, aligned_defaults, 1)
    elif aligned_defaults not in text:
        return text, False

    legacy_qemu_profile = '''            ram=DEFAULT_RAM_MB,
            smp=DEFAULT_SMP,
            mgmt_passthrough=True,
'''
    aligned_qemu_profile = '''            ram=DEFAULT_RAM_MB,
            cpu="host" if os.path.exists("/dev/kvm") else "max",
            mgmt_passthrough=True,
'''
    if legacy_qemu_profile in text:
        text = text.replace(
            legacy_qemu_profile,
            aligned_qemu_profile,
            1,
        )
    elif aligned_qemu_profile not in text:
        return text, False

    if MARKER in text:
        return text, True
    if "import datetime\n" not in text:
        return text, False
    text = text.replace(
        "import datetime\n",
        "import base64\nimport datetime\nimport select\nimport time\n",
        1,
    )
    class_anchor = "\n\nclass CumulusVX_vm(vrnetlab.VM):"
    if class_anchor not in text:
        return text, False
    text = text.replace(
        class_anchor,
        f"\n\n{MARKER}\n{_HELPERS}{class_anchor}",
        1,
    )
    init_anchor = '''        self.hostname = hostname
        self.num_nics = nics
        self.conn_mode = conn_mode
        self.nic_type = "virtio-net-pci"
'''
    init_replacement = '''        self.hostname = hostname
        self.conn_mode = conn_mode
        self._breakout_renames = _compute_renames(*_parse_breakout())
        self.num_nics = PREALLOCATED_DATA_NICS
        self.nic_type = f"virtio-net-pci,vectors={VIRTIO_NET_VECTORS}"
        self._bootstrap_done = False
        self._breakout_done = False
        self._console_buffer = b""
        self._login_deadline = time.monotonic() + LOGIN_READY_TIMEOUT
        self._readiness_deadline = 0.0
        self.degraded_reason = None
'''
    if init_anchor not in text:
        return text, False
    text = text.replace(init_anchor, init_replacement, 1)
    start = text.find("    def bootstrap_spin(self):")
    end = text.find("\n\nclass CumulusVX(vrnetlab.VR):", start)
    if start < 0 or end < 0:
        return text, False
    text = text[:start] + _BOOTSTRAP + text[end:]
    return text, True
