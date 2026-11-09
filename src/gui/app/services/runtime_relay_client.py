"""Async relay client; native sessions require a full qualified Docker ID."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import shlex

from fastapi import WebSocket

log = logging.getLogger(__name__)

READ_SIZE = 4096


class RuntimeRelayError(Exception):
    pass


class RuntimeRelayClient:
    async def connect_console(self, websocket: WebSocket, relay: dict) -> None:
        reader, writer = await self._open(relay, "CONNECT")
        try:
            log.info(
                "runtime relay console connected: %s via %s:%s",
                relay.get("container"), relay.get("host"), relay.get("port"),
            )
            await self._bridge(websocket, reader, writer)
        finally:
            log.info(
                "runtime relay console closing: %s via %s:%s",
                relay.get("container"), relay.get("host"), relay.get("port"),
            )
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def stream_logs(
        self,
        websocket: WebSocket,
        relay: dict,
        *,
        tail: int | str = 200,
        follow: bool = True,
    ) -> None:
        reader, writer = await self._open(
            relay,
            "LOG",
            str(tail),
            "1" if follow else "0",
        )
        try:
            while True:
                data = await reader.read(READ_SIZE)
                if not data:
                    break
                await websocket.send_text(data.decode(errors="replace"))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _open(self, relay: dict, action: str, *extra: str):
        backend=relay.get('runtime_backend')
        identity=relay.get('container_id')
        if backend not in (None,'custom'):
            raise RuntimeRelayError('unknown relay workload backend')
        if backend=='custom':
            if not isinstance(identity,str) or not re.fullmatch(r'[0-9a-f]{64}',identity):
                raise RuntimeRelayError('qualified native container identity required')
        elif identity is not None:
            raise RuntimeRelayError('container identity requires native relay context')
        host = relay["host"]
        port = int(relay["port"])
        reader, writer = await asyncio.open_connection(host, port)
        parts = [
            action+'_ID' if backend=='custom' else action,
            relay["api_key"],
            relay["container"],
            *([identity] if backend=='custom' else []),
            *extra,
        ]
        writer.write((" ".join(shlex.quote(p) for p in parts) + "\n").encode())
        await writer.drain()
        if action == "CONNECT":
            return reader, writer
        status = await reader.readline()
        text = status.decode(errors="replace").strip()
        if text != "OK":
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise RuntimeRelayError(text or "relay did not accept request")
        return reader, writer

    @staticmethod
    async def _bridge(
        websocket: WebSocket,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async def ws_to_relay():
            try:
                while True:
                    msg = await websocket.receive_text()
                    writer.write(msg.encode())
                    await writer.drain()
            except Exception:
                pass

        async def relay_to_ws():
            while True:
                data = await reader.read(READ_SIZE)
                if not data:
                    break
                await websocket.send_text(data.decode(errors="replace"))

        tasks = [
            asyncio.create_task(ws_to_relay()),
            asyncio.create_task(relay_to_ws()),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                with contextlib.suppress(Exception):
                    task.result()
        finally:
            for task in tasks:
                task.cancel()
