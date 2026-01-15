import requests
import threading

class PresenceWorker:
    """
    Periodically sends presence updates while a user is logged in.
    """
    def __init__(self, server_address: str, endpoint: str, interval_seconds: int = 10):
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
                response = requests.post(
                    f"{self.server_address}{self.endpoint}",
                    data={"online": "true"},
                    headers={"X-Session-Key": session_key}
                )
                response.raise_for_status()
            except requests.RequestException as e:
                # Swallow presence errors; keep trying until stopped
                with open('./errors/presence_errors.log', 'a') as f:
                    f.write(f'Presence update failed: {e}\n')
                continue
