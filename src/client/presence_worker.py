import os
import requests
import threading
from datetime import datetime, timezone
from Crypto.Hash import SHA256, HMAC

from .auth_utils import get_auth_headers

class PresenceWorker:
    """
    Periodically sends presence updates while a user is logged in.
    """
    def __init__(self, server_address: str, endpoint: str, interval_seconds: int = 3):
        self.server_address = server_address
        self.endpoint = endpoint
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, session_key: str):
        self.stop()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(session_key,), daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None

    def _run(self, session_key: str):
        while not self._stop_event.wait(self.interval_seconds):
            try:
                # 1. Presence uses an empty body
                request_body = ""
                
                # 2. Get headers explicitly tied to that empty body
                headers = get_auth_headers(session_key, request_body)
                headers['Content-Type'] = 'application/json'

                # 3. Send request
                response = requests.post(
                    f"{self.server_address}{self.endpoint}",
                    data=request_body,
                    headers=headers,
                    timeout=5 # Good practice to add a timeout for worker threads
                )
                response.raise_for_status()
            except requests.RequestException as e:
                os.makedirs('./errors', exist_ok=True)
                with open('./errors/presence_errors.log', 'a') as f:
                    f.write(f'[{datetime.now()}] Presence update failed: {e}\n')
                continue