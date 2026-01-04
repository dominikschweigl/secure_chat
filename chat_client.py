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
    """
    Manages storage of RSA keys for the user and their contacts.
    
    Directory structure:
    keys/
      {username}/
        private.pem      # User's own private key
        public.pem       # User's own public key
        contacts/
          {recipient_name}.pem  # Public keys of other users
    """
    def __init__(self, directory: str = "keys"):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def _get_user_dir(self, username: str) -> str:
        """Get the directory path for a specific user."""
        user_dir = os.path.join(self.directory, username)
        os.makedirs(user_dir, exist_ok=True)
        return user_dir
    
    def _get_contacts_dir(self, username: str) -> str:
        """Get the contacts directory path for a specific user."""
        contacts_dir = os.path.join(self._get_user_dir(username), "contacts")
        os.makedirs(contacts_dir, exist_ok=True)
        return contacts_dir

    def save_own_key(self, username: str, rsa_key: RSA.RsaKey):
        """
        Save the user's own RSA private key.
        
        Args:
            username: The username
            rsa_key: The RSA private key to save
        """
        if not rsa_key or not username:
            raise ValueError("RSA key or username not set.")
        
        user_dir = self._get_user_dir(username)
        private_key_path = os.path.join(user_dir, "private.pem")
        
        with open(private_key_path, "w") as f:
            f.write(rsa_key.export_key().decode("utf-8"))
        
        # Also save public key for convenience
        public_key_path = os.path.join(user_dir, "public.pem")
        with open(public_key_path, "w") as f:
            f.write(rsa_key.publickey().export_key().decode("utf-8"))

    def load_own_key(self, username: str) -> RSA.RsaKey:
        """
        Load the user's own RSA private key.
        
        Args:
            username: The username
            
        Returns:
            RSA.RsaKey: The private key
        """
        user_dir = self._get_user_dir(username)
        private_key_path = os.path.join(user_dir, "private.pem")
        
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"No private key found for user {username}")
        
        with open(private_key_path, "r") as f:
            return RSA.import_key(f.read())

    def save_contact_key(self, username: str, contact_username: str, public_key: RSA.RsaKey):
        """
        Save a contact's public key.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            public_key: The contact's RSA public key
        """
        if not public_key or not username or not contact_username:
            raise ValueError("Public key, username, or contact_username not set.")
        
        contacts_dir = self._get_contacts_dir(username)
        contact_key_path = os.path.join(contacts_dir, f"{contact_username}.pem")
        
        with open(contact_key_path, "w") as f:
            f.write(public_key.export_key().decode("utf-8"))

    def load_contact_key(self, username: str, contact_username: str) -> RSA.RsaKey | None:
        """
        Load a contact's public key if it exists.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            
        Returns:
            RSA.RsaKey | None: The contact's public key or None if not found
        """
        contacts_dir = self._get_contacts_dir(username)
        contact_key_path = os.path.join(contacts_dir, f"{contact_username}.pem")
        
        if not os.path.exists(contact_key_path):
            return None
        
        with open(contact_key_path, "r") as f:
            return RSA.import_key(f.read())
    
    def has_contact_key(self, username: str, contact_username: str) -> bool:
        """
        Check if a contact's public key is stored.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            
        Returns:
            bool: True if the contact's key exists
        """
        contacts_dir = self._get_contacts_dir(username)
        contact_key_path = os.path.join(contacts_dir, f"{contact_username}.pem")
        return os.path.exists(contact_key_path)

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
        # Cache for established symmetric keys
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
        self.keystore.save_own_key(username, rsa_key)

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
        self.rsa_key = self.keystore.load_own_key(username)

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
        First checks local keystore, then fetches from server if not cached.
        
        Args:
            username: The username of the target user
            
        Returns:
            RSA.RsaKey: The target user's public key
            
        Raises:
            RuntimeError: If the user does not exist (error in response)
            requests.exceptions.HTTPError: If the request fails
            requests.exceptions.RequestException: If the request fails
        """
        # Check if we have the contact's key stored locally
        cached_key = self.keystore.load_contact_key(self.username, username)
        if cached_key:
            return cached_key
        
        # Fetch from server
        endpoint = self.PUBLIC_KEY_ENDPOINT.format(username=username)
        response = requests.get(
            f"{self.server_address}{endpoint}"
        )
        response.raise_for_status()
        
        key_data = response.json()
        
        public_key_str = key_data.get('public-key')
        if not public_key_str:
            raise RuntimeError("No public key returned from server")
        
        public_key = RSA.import_key(public_key_str)
        
        # Cache the key locally
        self.keystore.save_contact_key(self.username, username, public_key)
        
        return public_key


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
