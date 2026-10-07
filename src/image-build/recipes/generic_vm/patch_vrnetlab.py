"""Use the dNLab bind mount for the vrnetlab QCOW2 overlay."""
from pathlib import Path
import re
import sys

ANCHOR = 'overlay_disk_image = re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)'

def patch(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^(?P<indent>[ \t]*){re.escape(ANCHOR)}$", text)
    if match is None or text.count(ANCHOR) != 1:
        raise SystemExit(f"{path}: vrnetlab overlay anchor changed")
    replacement = f'{match.group("indent")}overlay_disk_image = "/persist/overlay.qcow2"'
    path.write_text(text[:match.start()] + replacement + text[match.end():], encoding="utf-8")

if __name__ == "__main__":
    patch(Path(sys.argv[1]))
