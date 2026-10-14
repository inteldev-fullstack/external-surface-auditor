"""Start the local runner and open its browser UI after it is ready."""
import threading
import time
import socket
import webbrowser
import json
from urllib.request import urlopen
import uvicorn
from .main import app

URL = 'http://127.0.0.1:8765'


def open_when_ready():
    for _ in range(50):
        try:
            with urlopen(URL + '/api/health', timeout=1) as response:
                if json.loads(response.read()).get('mode') == 'local-staging-only':
                    webbrowser.open(URL)
                    return
        except Exception:
            time.sleep(.2)


def main():
    with socket.socket() as probe:
        occupied = probe.connect_ex(('127.0.0.1', 8765)) == 0
    if occupied:
        try:
            with urlopen(URL + '/api/health', timeout=2) as response:
                if json.loads(response.read()).get('mode') != 'local-staging-only':
                    raise ValueError()
            webbrowser.open(URL)
            print('External Surface Auditor is already running: ' + URL)
            return
        except Exception:
            raise SystemExit('Port 8765 is occupied by another service. Stop it and retry.')
    threading.Thread(target=open_when_ready, daemon=True).start()
    uvicorn.run(app, host='127.0.0.1', port=8765)


if __name__ == '__main__':
    main()
