#!/usr/bin/env python3
"""Install the FLiNOS recipe's persistent overlay hook into vrnetlab."""

from __future__ import annotations

import sys
from pathlib import Path


ANCHOR = 'overlay_disk_image = re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)'
REPLACEMENT = '''# dnlab-patched: persist-overlay-v1
        overlay_disk_image = (
            "/persist/overlay.qcow2" if os.path.isdir("/persist")
            else re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)
        )'''


def patch(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if source.count(ANCHOR) != 1:
        raise SystemExit(f"{path}: vrnetlab overlay anchor changed")
    path.write_text(source.replace(ANCHOR, REPLACEMENT), encoding="utf-8")


if __name__ == "__main__":
    patch(Path(sys.argv[1]))
