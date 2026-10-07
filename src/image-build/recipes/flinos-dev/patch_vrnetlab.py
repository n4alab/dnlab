"""Install the FLINOS development recipe's persistent overlay hook into vrnetlab."""
from __future__ import annotations

import sys
import re
from pathlib import Path


ANCHOR = 'overlay_disk_image = re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)'
MARKER = "# dnlab-patched: persist-overlay-v3"


def patch(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^(?P<indent>[ \t]*){re.escape(ANCHOR)}$", source)
    if match is None or source.count(ANCHOR) != 1:
        raise SystemExit(f"{path}: vrnetlab overlay anchor changed")
    indent = match.group("indent")
    replacement = f'{indent}{MARKER}\n{indent}overlay_disk_image = "/persist/overlay.qcow2"'
    path.write_text(source[:match.start()] + replacement + source[match.end():], encoding="utf-8")


if __name__ == "__main__":
    patch(Path(sys.argv[1]))
