import asyncio
import os
import sys
import threading
import webbrowser

import uvicorn

from app.backend.config import settings


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    url = f"http://localhost:{settings.port}/"

    if not settings.disable_auto_open:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    print(f"IOC Lookup Platform running at {url}")
    print("Press Ctrl+C to stop")

    try:
        uvicorn.run("app.backend.main:app", host=settings.host, port=settings.port, reload=settings.debug)
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    sys.exit(main() or 0)
