import asyncio
import os
import sys
import threading
import webbrowser

import uvicorn


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "").lower() == "true"
    url = f"http://localhost:{port}/"

    if os.getenv("DISABLE_AUTO_OPEN") != "1":
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    print(f"IOC Lookup Platform running at {url}")
    print("Press Ctrl+C to stop")

    try:
        uvicorn.run("app.backend.main:app", host=host, port=port, reload=debug)
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    sys.exit(main() or 0)
