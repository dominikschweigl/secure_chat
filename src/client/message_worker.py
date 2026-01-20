import threading
import requests
from typing import List, Dict
from datetime import datetime, timezone
from Crypto.Hash import SHA256, HMAC

from .auth_utils import get_auth_headers

class MessageWorker:
    """
    Periodically polls for new messages from the user's inbox.
    """
    def __init__(self, server_address: str, endpoint: str, interval_seconds: int = 1):
        self.server_address = server_address
        self.endpoint = endpoint
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._session_key: str | None = None
        self._callback = None

    def start(self, session_key: str, callback):
        self.stop()
        self._session_key = session_key
        self._callback = callback
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None
        self._session_key = None
        self._callback = None

    def _fetch_messages(self) -> List[Dict]:
        """Fetch messages from the server using explicit empty-body signature."""
        if not self._session_key:
            return []
            
        try:
            # For GET requests, the body used for signature calculation 
            # MUST be an empty string to match the server-side get_current_user logic.
            request_body = "" 
            headers = get_auth_headers(self._session_key, request_body)
            
            response = requests.get(
                f"{self.server_address}{self.endpoint}",
                headers=headers,
                timeout=5
            )
            response.raise_for_status()
            return response.json().get('messages', [])
        except requests.RequestException as e:
            # Optional: Log errors for debugging 401s
            # print(f"Polling error: {e}")
            return []

    def _run(self):
        while not self._stop_event.wait(self.interval_seconds):
            try:
                messages = self._fetch_messages()
                if messages and self._callback:
                    self._callback(messages)
            except Exception:
                continue