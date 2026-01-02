import os
import requests
from Crypto.PublicKey import RSA
import threading

class KeyStore:
    def __init__(self, directory: str = "keys"):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def save_private_key(self, username: str, rsa_key: RSA.RsaKey):
        if not rsa_key or not username:
            raise ValueError("RSA key or username not set.")
        
        key_path = os.path.join(self.directory, f"{username}_private.pem")
        with open(key_path, "w") as f:
            f.write(rsa_key.export_key().decode("utf-8"))

    def load_private_key(self, username: str) -> RSA.RsaKey:
        key_path = os.path.join(self.directory, f"{username}_private.pem")
        with open(key_path, "r") as f:
            return RSA.import_key(f.read())

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
                requests.post(
                    f"{self.server_address}{self.endpoint}", 
                    data={"session-key": session_key}
                )
            except requests.RequestException:
                # Swallow presence errors; keep trying until stopped
                continue


class ChatClient:

    REGISTER_ENDPOINT = "/chat/register"
    LOGIN_ENDPOINT = "/chat/login"
    LOGOUT_ENDPOINT = "/chat/logout"
    PRESENCE_ENDPOINT = "/chat/presence"

    def __init__(self, server_address: str, keystore: KeyStore | None = None):
        self.server_address: str = server_address
        self.username: str = None
        self.logged_in: bool = False
        self.session_key: str = None
        self.rsa_key: RSA.RsaKey = None
        self.keystore = keystore or KeyStore()
        self.presence = PresenceWorker(server_address, self.PRESENCE_ENDPOINT)

    def register(self, username: str, password: str):
        """
        Register a new user with the given username and password.
        
        Raises:
            requests.exceptions.HTTPError: If registration fails (409 for existing username)
            requests.exceptions.RequestException: If the request fails
        """
        # generate user rsa key pair
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.public_key().export_key().decode('utf-8')
        
        response = requests.post(
            f"{self.server_address}{self.REGISTER_ENDPOINT}", 
            data={'username': username, 'password': password, 'public-key': public_key}
        )
        response.raise_for_status()

        self.username = username
        self.rsa_key = rsa_key
        self.keystore.save_private_key(username, rsa_key)

    def login(self, username: str, password: str):
        """
        Log in a user with their credentials.
        
        Raises:
            requests.exceptions.HTTPError: If login fails (401 for invalid password, 404 for non-existent username)
            requests.exceptions.RequestException: If the request fails
        """
        response = requests.post(
            f"{self.server_address}{self.LOGIN_ENDPOINT}", 
            data={'username': username, 'password': password}
        )
        response.raise_for_status()

        session_key = response.json().get('session-key')

        self.username = username
        self.session_key = session_key
        self.logged_in = True

        # load private key for this user
        self.rsa_key = self.keystore.load_private_key(username)

        # start presence heartbeats
        self.presence.start(session_key)

    def logout(self):
        """
        Log out the user.
        
        Raises:
            RuntimeError: If the user is not logged in
            requests.exceptions.HTTPError: If logout request fails
            requests.exceptions.RequestException: If the request fails
        """
        if not self.logged_in:
            raise RuntimeError("You are not logged in.")
        
        response = requests.post(
            f"{self.server_address}{self.LOGOUT_ENDPOINT}", 
            data={'session-key': self.session_key}
        )
        response.raise_for_status()

        # stop presence heartbeats
        self.presence.stop()

        self.username = None
        self.logged_in = False
        self.session_key = None
        self.rsa_key = None

    def send_message(self, message: str):
        # TODO: implement message sending
        
        if not self.logged_in:
            print("You must be connected to send messages.")
            return
        print(f"{self.username}: {message}")