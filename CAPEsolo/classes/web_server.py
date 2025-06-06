import http.server
import socket
import socketserver
import threading
import webbrowser
from functools import partial
from pathlib import Path


class LocalWebServer:
    def __init__(self, serveDir: Path, port: int = 8888):
        self.serveDir = Path(serveDir).resolve()
        self.port = port
        self._serverThread = None
        self._isRunning = False

    def IsPortOpen(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            return sock.connect_ex(('localhost', self.port)) == 0

    def Start(self):
        if self.IsPortOpen():
            self._isRunning = True
            return

        handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(self.serveDir))

        def RunServer():
            with socketserver.TCPServer(("", self.port), handler) as httpd:
                httpd.serve_forever()

        self._serverThread = threading.Thread(target=RunServer, daemon=True)
        self._serverThread.start()
        self._isRunning = True

    def OpenBrowser(self, htmlFile: str = "viewer.html"):
        url = f"http://localhost:{self.port}/{htmlFile}"
        webbrowser.open(url)

    def IsRunning(self) -> bool:
        """Return True if the server is running or reused."""
        return self._isRunning