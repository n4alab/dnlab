"""Safe, lab-correlated view of the dNLab operational logs.

The GUI must never expose arbitrary host files or unfiltered stack logs.  This
service reads a fixed allow-list below ``log_root`` and emits only records that
carry the resolved lab UUID, display name or deterministic netname.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from app.services.lab_resolver import ResolvedLab


class LabLogService:
    _FILES = {
        "gui": "gui/dnlab-gui.log",
        "multinode": "multinode/dnlab-multinode.log",
        "lab-cleanup": "lab-cleanup/dnlab-lab-cleanup.log",
    }
    _MAX_READ = 512 * 1024

    async def stream(self, websocket, lab: ResolvedLab) -> None:
        offsets: dict[Path, int] = {}
        while True:
            for service, relative in self._FILES.items():
                path = Path(settings.LOG_DIR).parent / relative
                chunk, offsets[path] = await asyncio.to_thread(self._read_new, path, offsets.get(path, 0))
                for line in chunk.splitlines():
                    if self._belongs_to_lab(line, lab):
                        await websocket.send_json({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "service": service,
                            "level": self._level(line),
                            "message": line,
                        })
            await asyncio.sleep(1)

    @classmethod
    def _read_new(cls, path: Path, offset: int) -> tuple[str, int]:
        try:
            size = path.stat().st_size
            # Rotation/truncation: restart from the last bounded window.
            if offset == 0 and size > cls._MAX_READ:
                offset = size - cls._MAX_READ
            elif offset > size:
                offset = max(0, size - cls._MAX_READ)
            with path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(cls._MAX_READ)
                return data.decode(errors="replace"), handle.tell()
        except OSError:
            return "", offset

    @staticmethod
    def _belongs_to_lab(line: str, lab: ResolvedLab) -> bool:
        # Display names are deliberately excluded: two users may choose the
        # same name. UUID and netname are deterministic, unique correlators.
        markers = (str(lab.id), lab.netname)
        return any(marker and marker in line for marker in markers)

    @staticmethod
    def _level(line: str) -> str:
        upper = line.upper()
        if "ERROR" in upper or "EXCEPTION" in upper or "FAILED" in upper:
            return "error"
        if "WARNING" in upper or "WARN" in upper:
            return "warning"
        return "info"
