import threading
import requests
from typing import List, Dict


class MessageWorker:
    """
    Periodically polls for new messages from the user's inbox.
    """
    def __init__(self, server_address: str, endpoint: str, interval_seconds: int = 2):
        self.server_address = server_address
        self.endpoint = endpoint
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._session_key: str | None = None
        self._callback = None

    def start(self, session_key: str, callback):
        """
        Start polling for messages.
        
        Args:
            session_key: The session key for authentication
            callback: Function to call with fetched messages (receives list of message dicts)
        """
        self.stop()
        self._session_key = session_key
        self._callback = callback
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None
        self._session_key = None
        self._callback = None

    def _fetch_messages(self) -> List[Dict]:
        """Fetch messages from the server."""
        if not self._session_key:
            return []
            
        try:
            response = requests.get(
                f"{self.server_address}{self.endpoint}",
                headers={"X-Session-Key": self._session_key}
            )
            response.raise_for_status()
            return response.json().get('messages', [])
        except requests.RequestException:
            return []

    def _run(self):
        while not self._stop_event.wait(self.interval_seconds):
            try:
                messages = self._fetch_messages()
                if messages and self._callback:
                    self._callback(messages)
            except Exception:
                # Swallow errors; keep trying until stopped
                continue
