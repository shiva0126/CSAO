from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import struct
import subprocess
import termios
from typing import List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.tool_check import TOOL_USAGE
from workbench.auth import ROLE_ANALYST, SESSION_COOKIE, has_role
from workbench.singletons import auth_manager

router = APIRouter(tags=["terminal"])

WORKER_CONTAINER = "csao_worker"

# Requires `docker` on PATH and permission to exec into WORKER_CONTAINER --
# true when this process runs on the same host as `docker compose up`,
# which is the only deployment shape this app currently assumes (see
# README.md). Every session execs into the worker container specifically,
# never the host shell, so it's bounded by the same read-only AWS access
# the assessment engine already has.


def _build_argv(tool_key: str) -> List[str]:
    meta = TOOL_USAGE[tool_key]
    help_cmd = meta["help_command"]
    banner = f"--- {meta['name']} -- interactive shell in the worker container ---"
    inner = f"{help_cmd} 2>&1 | head -100; echo; echo \"{banner}\"; echo; exec sh"
    return ["docker", "exec", "-it", WORKER_CONTAINER, "sh", "-c", inner]


async def _bridge_pty_to_websocket(websocket: WebSocket, argv: List[str]) -> None:
    master_fd, slave_fd = pty.openpty()
    process = subprocess.Popen(
        argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        # Makes the child a session leader so the pty becomes its
        # controlling terminal. Deliberately not `preexec_fn=os.setsid`:
        # Python's own docs warn preexec_fn is unsafe in a multi-threaded
        # process (a running asyncio/uvicorn server has threads) since the
        # forked child can deadlock running arbitrary Python before exec.
        # start_new_session does the same setsid() natively around the
        # fork+exec instead of via a Python callback.
        start_new_session=True,
    )
    os.close(slave_fd)

    loop = asyncio.get_event_loop()
    output_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def _on_readable() -> None:
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            chunk = b""
        output_queue.put_nowait(chunk)
        if not chunk:
            loop.remove_reader(master_fd)

    loop.add_reader(master_fd, _on_readable)

    async def _pump_output() -> None:
        while True:
            chunk = await output_queue.get()
            if not chunk:
                # The child process (docker exec) exited -- e.g. the worker
                # container isn't running, or `docker` isn't on this host's
                # PATH. Without this, the outer receive loop below would
                # wait forever on client input that can no longer go
                # anywhere, leaving the browser terminal looking "stuck"
                # with no indication the session ended.
                await websocket.close()
                return
            await websocket.send_bytes(chunk)

    pump_task = asyncio.create_task(_pump_output())
    try:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            text = message.get("text")
            if text is not None:
                try:
                    control = json.loads(text)
                except ValueError:
                    continue
                if isinstance(control, dict) and control.get("type") == "resize":
                    rows = max(1, int(control.get("rows", 24)))
                    cols = max(1, int(control.get("cols", 80)))
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                continue
            data = message.get("bytes")
            if data:
                os.write(master_fd, data)
    except WebSocketDisconnect:
        pass
    finally:
        pump_task.cancel()
        try:
            loop.remove_reader(master_fd)
        except (ValueError, OSError):
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


@router.websocket("/tools/{tool_key}/terminal")
async def tool_terminal(websocket: WebSocket, tool_key: str) -> None:
    token = websocket.cookies.get(SESSION_COOKIE, "")
    user = auth_manager.session_user(token)
    if user is None or not has_role(user, ROLE_ANALYST):
        # Accept first: a close code sent before accept() never actually
        # reaches the client as a WS close code (it just shows up as a
        # generic HTTP 403 at the handshake level), so there's no way to
        # tell the analyst *why* without accepting and writing a message.
        await websocket.accept()
        await websocket.send_bytes(b"Access denied: this terminal requires an Analyst or Administrator role.\r\n")
        await websocket.close(code=1008)
        return
    if tool_key not in TOOL_USAGE:
        await websocket.accept()
        await websocket.send_bytes(f"Unknown tool: {tool_key}\r\n".encode())
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        await _bridge_pty_to_websocket(websocket, _build_argv(tool_key))
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
