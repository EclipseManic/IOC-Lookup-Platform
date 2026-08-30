import asyncio
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser

import uvicorn

from app.backend.config import settings


def _port_in_use(host: str, port: int) -> bool:
    """Return True when nothing can bind the target host:port.

    The socket family is derived from the host so IPv6 addresses (e.g. ``::1``)
    probe correctly instead of failing on an AF_INET socket.
    """
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except socket.gaierror:
        # Unresolvable host: report as unavailable so uvicorn surfaces the error.
        return True
    for _family, _socktype, _proto, _canonname, address in infos:
        sock = socket.socket(_family, socket.SOCK_STREAM)
        try:
            sock.bind(address)
            return False
        except OSError:
            continue
        finally:
            sock.close()
    return True


def _local_has_port(local: str, port: int) -> bool:
    """Match a netstat local address (127.0.0.1:8000, [::1]:8000, 0.0.0.0:8000) against a port."""
    if local.startswith("["):
        end = local.rfind("]")
        if end == -1:
            return False
        address = local[end + 2:]
    else:
        address = local.rsplit(":", 1)[-1]
    return address == str(port)


def _find_pid_on_port(port: int) -> int | None:
    """Find the PID of the process LISTENING on the given port via netstat."""
    try:
        output = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if parts[3] != "LISTENING":
            continue
        if not _local_has_port(parts[1], port):
            continue
        try:
            return int(parts[-1])
        except ValueError:
            continue
    return None


def _kill_process(pid: int) -> bool:
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _stop_owner(port: int) -> bool:
    """Force-stop whatever owns the port, re-checking until it frees.

    uvicorn's reloader spawns a child worker, so the first kill may leave the
    child behind; loop until nothing owns the port anymore.
    """
    for _ in range(10):
        pid = _find_pid_on_port(port)
        if pid is None:
            return True
        if pid == os.getpid():
            return True
        _kill_process(pid)
        time.sleep(0.5)
    return _find_pid_on_port(port) is None


def _resolve_port_conflict(host: str, port: int) -> str:
    """Ask the user what to do when the port is already taken.

    Returns "start" (kill the current listener and boot a fresh server),
    "keep" (use the running server), or "abort".
    """
    print(f"PORT CONFLICT: {host}:{port} is already in use.")
    pid = _find_pid_on_port(port)
    if pid is not None:
        print(f"  The running server was started by PID {pid}.")
    print("  (1) Stop the running server and start a fresh one")
    print("  (2) Keep using the already-running server and exit")
    while True:
        try:
            choice = input("  Choose [1/2]: ").strip().lower()
        except EOFError:
            # Non-interactive runs never kill anything on their own.
            return "keep"
        if choice == "1":
            if pid is None:
                print(
                    "  Could not identify the process owning the port. Stop it "
                    "manually (e.g. `netstat -ano | findstr :{port}`) and rerun."
                )
                return "abort"
            if not _stop_owner(port):
                print("  Could not free the port. Stop the process manually and rerun.")
                return "abort"
            return "start"
        if choice == "2":
            return "keep"
        print("  Please enter 1 or 2.")


def _display_url() -> str:
    """A URL the user can open locally, even when the bind host is 0.0.0.0."""
    host = settings.host
    if host in ("0.0.0.0", "::", ""):
        host = "localhost"
    return f"http://{host}:{settings.port}/"


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    while True:
        if _port_in_use(settings.host, settings.port):
            action = _resolve_port_conflict(settings.host, settings.port)
            if action == "keep":
                print(f"Using the already-running server at {_display_url()}")
                print("Nothing to do - reopen the page above.")
                return
            if action == "abort":
                return
            # action == "start": the previous owner is dead; boot below.

        url = _display_url()
        if not settings.disable_auto_open:
            threading.Timer(1.5, lambda: webbrowser.open(url)).start()

        print(f"IOC Lookup Platform running at {url}")
        print("Press Ctrl+C to stop")

        try:
            uvicorn.run(
                "app.backend.main:app",
                host=settings.host,
                port=settings.port,
                reload=settings.debug,
                reload_excludes=["data/*", "*.pyc", "__pycache__/*"],
            )
            return
        except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
            return
        except OSError as error:
            # Lost the probe-to-bind race: someone grabbed the port in between.
            if _port_in_use(settings.host, settings.port):
                print(f"WARN: {settings.host}:{settings.port} was taken between the "
                      f"check and start ({error}); re-checking...")
                continue
            raise


if __name__ == "__main__":
    sys.exit(main() or 0)