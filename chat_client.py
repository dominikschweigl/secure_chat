import os
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad
import threading
import base64

class KeyStore:
    def __init__(self, directory: str = "keys"):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def save_rsa_key(self, username: str, rsa_key: RSA.RsaKey):
        if not rsa_key or not username:
            raise ValueError("RSA key or username not set.")
        
        key_path = os.path.join(self.directory, f"{username}_private.pem")
        with open(key_path, "w") as f:
            f.write(rsa_key.export_key().decode("utf-8"))

    def load_rsa_key(self, username: str) -> RSA.RsaKey:
        key_path = os.path.join(self.directory, f"{username}_private.pem")
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"No RSA key found for user {username}")
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
    USERS_ENDPOINT = "/chat/users"
    PUBLIC_KEY_ENDPOINT = "/chat/{username}/publickey"
    MESSAGE_ENDPOINT = "/chat/{username}"
    KEY_EXCHANGE_ENDPOINT = "/chat/{username}/keyexchange"

    def __init__(self, server_address: str, keystore: KeyStore | None = None):
        self.server_address: str = server_address
        self.username: str = None
        self.logged_in: bool = False
        self.session_key: str = None
        self.rsa_key: RSA.RsaKey = None
        self.keystore = keystore or KeyStore()
        self.presence = PresenceWorker(server_address, self.PRESENCE_ENDPOINT)
        # Cache for recipient public keys to avoid repeated fetches
        self.recipient_public_keys: dict[str, RSA.RsaKey] = {}
        # Cache for established symmetric keys (DH key exchange results)
        self.symmetric_keys: dict[str, bytes] = {}

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
        self.keystore.save_rsa_key(username, rsa_key)

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
        self.rsa_key = self.keystore.load_rsa_key(username)

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

    def get_users(self):
        """
        Get list of currently registered/online users.
        
        Returns:
            list: List of active usernames
            
        Raises:
            requests.exceptions.HTTPError: If the request fails
            requests.exceptions.RequestException: If the request fails
        """
        response = requests.get(
            f"{self.server_address}{self.USERS_ENDPOINT}"
        )
        response.raise_for_status()
        
        users_data = response.json()
        
        return users_data.get('users', [])
    
    def send_message(self, recipient_username: str, message: str) -> None:
        """
        Send an encrypted message to a user.
        
        The message is encrypted using AES with a symmetric key that is established
        once per recipient and cached for subsequent messages.
        The server automatically adds sender username and timestamp,
        and pushes the encrypted message into the recipient's Kafka queue.
        
        Args:
            recipient_username: The username of the message recipient
            message: The plaintext message content to send
            
        Returns:
            None
            
        Raises:
            RuntimeError: If not logged in or if the server returns an error
            requests.exceptions.HTTPError: If the request fails
            requests.exceptions.RequestException: If the request fails
        """
        if not self.is_logged_in():
            raise RuntimeError("You must be logged in to send messages.")
        
        # Get or establish symmetric key with recipient
        symmetric_key = self._get_or_establish_symmetric_key(recipient_username)
        
        # Encrypt the message
        encrypted_message = self._encrypt_message(message, symmetric_key)
        
        endpoint = self.MESSAGE_ENDPOINT.format(username=recipient_username)
        response = requests.post(
            f"{self.server_address}{endpoint}",
            data={'message': encrypted_message}
        )

        response.raise_for_status()


    def _get_or_establish_symmetric_key(self, recipient_username: str) -> bytes:
        """
        Get or establish a symmetric key with a recipient.
        
        Generates a random AES symmetric key for this recipient.
        The key is encrypted with the recipient's RSA public key for secure transmission.
        
        Args:
            recipient_username: The username of the message recipient
            
        Returns:
            bytes: The 256-bit AES symmetric key for encrypting messages
        """
        # Check if we already have a symmetric key for this recipient
        if recipient_username in self.symmetric_keys:
            return self.symmetric_keys[recipient_username]
        
        # Generate a new random symmetric key (32 bytes = 256 bits)
        symmetric_key = get_random_bytes(32)
        
        # Cache the symmetric key for this recipient
        self.symmetric_keys[recipient_username] = symmetric_key
        
        self._send_symmetric_key(recipient_username, symmetric_key)
        
        return symmetric_key

    
    def _send_symmetric_key(self, recipient_username: str, symmetric_key: bytes):
        recipient_rsa_key = self._get_public_key(recipient_username)
        cipher_rsa = PKCS1_OAEP.new(recipient_rsa_key)
        encrypted_key = base64.b64encode(cipher_rsa.encrypt(symmetric_key)).decode('utf-8')
        
        endpoint = self.KEY_EXCHANGE_ENDPOINT.format(username=recipient_username)
        response = requests.post(
            f"{self.server_address}{endpoint}",
            data={'encrypted_key': encrypted_key}
        )
        response.raise_for_status()
    

    def _get_public_key(self, username: str):
        """
        Get the public key for a target user to initialize chat.
        
        Args:
            username: The username of the target user
            
        Returns:
            RSA.RsaKey: The target user's public key
            
        Raises:
            RuntimeError: If the user does not exist (error in response)
            requests.exceptions.HTTPError: If the request fails
            requests.exceptions.RequestException: If the request fails
        """
        endpoint = self.PUBLIC_KEY_ENDPOINT.format(username=username)
        response = requests.get(
            f"{self.server_address}{endpoint}"
        )
        response.raise_for_status()
        
        key_data = response.json()
        
        public_key_str = key_data.get('public-key')
        if not public_key_str:
            raise RuntimeError("No public key returned from server")
        
        return RSA.import_key(public_key_str)


    def _encrypt_message(self, message: str, symmetric_key: bytes) -> str:
        """
        Encrypt a message using AES-CBC with HMAC authentication.
        
        Args:
            message: The plaintext message to encrypt
            symmetric_key: The AES symmetric key (32 bytes)
            
        Returns:
            str: Base64-encoded encrypted message with IV and HMAC
        """
        # Generate random IV for CBC mode
        iv = get_random_bytes(16)  # AES block size is 16 bytes
        
        # Encrypt using AES-CBC with PKCS7 padding
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        
        # Compute HMAC for authentication (using same symmetric key)
        hmac = HMAC.new(symmetric_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        tag = hmac.digest()
        
        # Combine IV, ciphertext, and HMAC tag, then base64 encode
        encrypted_data = iv + ciphertext + tag
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def is_logged_in(self) -> bool:
        return self.logged_in
