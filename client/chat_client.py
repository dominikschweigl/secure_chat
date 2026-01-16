import json
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad, unpad
import base64
import threading

from .key_store import KeyStore
from .presence_worker import PresenceWorker
from .message_store import MessageStore
from .message_worker import MessageWorker

class ChatClient:

    REGISTER_ENDPOINT = "/chat/auth/register"
    LOGIN_ENDPOINT = "/chat/auth/login"
    LOGOUT_ENDPOINT = "/chat/auth/logout"
    PRESENCE_ENDPOINT = "/presence"
    USERS_ENDPOINT = "/chat/users"
    PUBLIC_KEY_ENDPOINT = "/chat/{username}/publickey"
    MESSAGE_ENDPOINT = "/chat/{username}/send"
    KEY_EXCHANGE_ENDPOINT = "/chat/{username}/keyexchange"
    MESSAGES_ENDPOINT = "/chat/messages"
    GET_KEY_EXCHANGES_ENDPOINT = "/chat/keyexchange"

    def __init__(self, server_address: str, keystore: KeyStore | None = None):
        self.server_address: str = server_address
        self.username: str = None
        self.logged_in: bool = False
        self.session_key: str = None
        self.rsa_key: RSA.RsaKey = None
        self.keystore = keystore or KeyStore()
        self.message_store = MessageStore()
        self.presence = PresenceWorker(server_address, self.PRESENCE_ENDPOINT)
        self.message_worker = MessageWorker(server_address, self.MESSAGES_ENDPOINT)
        # Cache for established symmetric keys
        self.symmetric_keys: dict[str, bytes] = {}
        
        # Thread locks for thread safety
        self._state_lock = threading.RLock()  # Protects login state (username, logged_in, session_key)
        self._keys_lock = threading.RLock()   # Protects symmetric_keys dict
        
        # Event callbacks for reactive UI
        self.on_message_received = None  # Callback(sender: str, message: str, timestamp: str)
        self.on_message_sent = None      # Callback(recipient: str, message: str)
        self.on_login = None             # Callback(username: str)
        self.on_logout = None            # Callback()
        self.on_error = None             # Callback(error: str)

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

        hashed_password = SHA256.new(password.encode('utf-8')).hexdigest()
        
        response = requests.post(
            f"{self.server_address}{self.REGISTER_ENDPOINT}", 
            json={'username': username, 'password': hashed_password, 'public-key': public_key}
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
        hashed_password = SHA256.new(password.encode('utf-8')).hexdigest()

        response = requests.post(
            f"{self.server_address}{self.LOGIN_ENDPOINT}", 
            json={'username': username, 'password': hashed_password}
        )
        response.raise_for_status()

        # load private key for this user
        self.rsa_key = self.keystore.load_own_key(username)

        # encryption: cipher_rsa.encrypt(raw_key.encode()).hex()
        encrypted_session_key = response.json().get('session-key')

        cipher_rsa = PKCS1_OAEP.new(self.rsa_key, hashAlgo=SHA256)
        decrypted_session_key = cipher_rsa.decrypt(bytes.fromhex(encrypted_session_key))
        session_key = decrypted_session_key.decode('utf-8')

        # Write session key to file
        with open(f"keys/{username}/session_key.txt", "w") as f:
            f.write(session_key)

        with self._state_lock:
            self.username = username
            self.session_key = session_key
            self.logged_in = True

        # start presence heartbeats
        self.presence.start(session_key)
        
        # start message polling
        self.message_worker.start(session_key, self._process_messages)
        
        # Trigger login callback
        if self.on_login:
            self.on_login(username)

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
            headers={'X-Session-Key': self.session_key}
        )
        response.raise_for_status()

        # stop presence heartbeats
        self.presence.stop()
        
        # stop message polling
        self.message_worker.stop()

        with self._state_lock:
            self.username = None
            self.logged_in = False
            self.session_key = None
            self.rsa_key = None
        
        # Trigger logout callback
        if self.on_logout:
            self.on_logout()

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
            f"{self.server_address}{self.USERS_ENDPOINT}",
            headers={'X-Session-Key': self.session_key}
        )
        response.raise_for_status()
        
        users_data = response.json()

        with open(f"keys/{self.username}/users.json", "w") as f:
            f.write(json.dumps(users_data, indent=4))
        
        return users_data
    
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
        
        if recipient_username != self.username:
            # Get or establish symmetric key with recipient
            symmetric_key = self._get_or_establish_symmetric_key(recipient_username)
            
            # Encrypt the message
            encrypted_message = self._encrypt_message(message, symmetric_key)
            
            endpoint = self.MESSAGE_ENDPOINT.format(username=recipient_username)
            response = requests.post(
                f"{self.server_address}{endpoint}",
                json={'message': encrypted_message},
                headers={'X-Session-Key': self.session_key}
            )

            response.raise_for_status()

        self.message_store.save_message(
            self.username, recipient_username,
            sender=self.username,
            recipient=recipient_username,
            message=message,
            encrypted=False
        )
        
        # Trigger message sent callback
        if self.on_message_sent:
            self.on_message_sent(recipient_username, message)


    def _get_symmetric_key(self, contact_username: str) -> bytes | None:
        """
        Get an existing symmetric key with a contact.
        Does NOT establish a new key if one doesn't exist.
        
        If the key is not found locally, checks Kafka for any received key exchange messages
        and stores all received keys before returning the requested key.
        
        Args:
            contact_username: The contact's username
            
        Returns:
            bytes | None: The symmetric key if it exists, None otherwise
        """
        with self._keys_lock:
            # Check memory cache first
            if contact_username in self.symmetric_keys:
                return self.symmetric_keys[contact_username]
            
            # Check keystore
            with self._state_lock:
                current_username = self.username
            
            stored_key = self.keystore.load_symmetric_key(current_username, contact_username)
            if stored_key:
                # Cache in memory for faster access
                self.symmetric_keys[contact_username] = stored_key
                return stored_key
        
        # Not found locally - check Kafka for received key exchanges
        self._fetch_and_process_key_exchanges()
        
        # Check again after processing Kafka messages
        with self._keys_lock:
            if contact_username in self.symmetric_keys:
                return self.symmetric_keys[contact_username]
            
            return None

    def _get_or_establish_symmetric_key(self, recipient_username: str) -> bytes:
        """
        Get or establish a symmetric key with a recipient.
        
        First checks for existing key, then generates a new one if needed.
        The key is encrypted with the recipient's RSA public key for secure transmission.
        
        Args:
            recipient_username: The username of the message recipient
            
        Returns:
            bytes: The 256-bit AES symmetric key for encrypting messages
        """
        # Try to get existing key first
        existing_key = self._get_symmetric_key(recipient_username)
        if existing_key:
            return existing_key
        
        # No existing key, establish a new one
        with self._keys_lock:
            with self._state_lock:
                current_username = self.username
            
            # Generate a new random symmetric key (32 bytes = 256 bits)
            symmetric_key = get_random_bytes(32)
            
            # Cache in memory
            self.symmetric_keys[recipient_username] = symmetric_key
            
            # Save to keystore
            self.keystore.save_symmetric_key(current_username, recipient_username, symmetric_key)
            
            self._send_symmetric_key(recipient_username, symmetric_key)
            
            return symmetric_key

    
    def _send_symmetric_key(self, recipient_username: str, symmetric_key: bytes):
        recipient_rsa_key = self._get_public_key(recipient_username)
        cipher_rsa = PKCS1_OAEP.new(recipient_rsa_key)
        encrypted_key = base64.b64encode(cipher_rsa.encrypt(symmetric_key)).decode('utf-8')
        
        with open('./errors/decryption.log', 'a') as f:
            f.write(f'Sending symmetric key to {recipient_username}\n')
        
        endpoint = self.KEY_EXCHANGE_ENDPOINT.format(username=recipient_username)
        response = requests.post(
            f"{self.server_address}{endpoint}",
            json={'encrypted_key': encrypted_key, "sender": self.username},
            headers={'X-Session-Key': self.session_key}
        )
        response.raise_for_status()
        
        with open('./errors/decryption.log', 'a') as f:
            f.write(f'✓ Symmetric key sent to {recipient_username}\n')
    
    def _fetch_and_process_key_exchanges(self) -> None:
        """
        Fetch key exchange messages from the dedicated Kafka queue and decrypt/store all received symmetric keys.
        This is called when looking for a key that doesn't exist locally.
        """
        if not self.is_logged_in():
            with open('./errors/decryption.log', 'a') as f:
                f.write('Not logged in, skipping key exchange fetch\n')
            return
        
        try:
            # Fetch key exchange messages from the dedicated queue
            with open('./errors/decryption.log', 'a') as f:
                f.write(f'Fetching key exchanges from {self.GET_KEY_EXCHANGES_ENDPOINT}\n')
            
            response = requests.get(
                f"{self.server_address}{self.GET_KEY_EXCHANGES_ENDPOINT}",
                headers={'X-Session-Key': self.session_key}
            )
            response.raise_for_status()
            key_exchanges = response.json().get('keys', [])
            
            with open('./errors/decryption.log', 'a') as f:
                f.write(f'Fetched {len(key_exchanges)} key exchange messages\n')
            
            # Process all received key exchange messages
            for key_msg in key_exchanges:
                sender = key_msg.get('sender')
                encrypted_key = key_msg.get('encrypted_key')
                
                with open('./errors/decryption.log', 'a') as f:
                    f.write(f'Processing key exchange from {sender}\n')
                
                if sender and encrypted_key:
                    try:
                        # Decrypt the symmetric key using our RSA private key
                        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
                        encrypted_key_bytes = base64.b64decode(encrypted_key)
                        symmetric_key = cipher_rsa.decrypt(encrypted_key_bytes)
                        
                        # Store the key
                        with self._keys_lock:
                            self.symmetric_keys[sender] = symmetric_key
                            with self._state_lock:
                                current_username = self.username
                            self.keystore.save_symmetric_key(current_username, sender, symmetric_key)
                        
                        with open('./errors/decryption.log', 'a') as f:
                            f.write(f'✓ Received and stored symmetric key from {sender}\n')
                    except Exception as e:
                        with open('./errors/decryption.log', 'a') as f:
                            f.write(f'Failed to decrypt key from {sender}: {e}\n')
        except Exception as e:
            with open('./errors/decryption.log', 'a') as f:
                f.write(f'Failed to fetch key exchanges: {e}\n')

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
            f"{self.server_address}{endpoint}",
            headers={'X-Session-Key': self.session_key}
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
    
    def _decrypt_message(self, encrypted_message: str, symmetric_key: bytes) -> str:
        """
        Decrypt a message using AES-CBC and verify HMAC authentication.
        
        Args:
            encrypted_message: Base64-encoded encrypted message with IV and HMAC
            symmetric_key: The AES symmetric key (32 bytes)
            
        Returns:
            str: The decrypted plaintext message
            
        Raises:
            ValueError: If HMAC verification fails
        """
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_message)
        
        # Extract components: IV (16 bytes) + ciphertext + HMAC (32 bytes)
        iv = encrypted_data[:16]
        hmac_tag = encrypted_data[-32:]
        ciphertext = encrypted_data[16:-32]
        
        # Verify HMAC
        hmac = HMAC.new(symmetric_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        hmac.verify(hmac_tag)
        
        # Decrypt
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')
    
    def _process_messages(self, messages):
        """
        Process fetched messages: decrypt and store in MessageStore.
        Called as a callback by MessageWorker.
        
        Args:
            messages: List of message objects from the server
        """
        with self._state_lock:
            if not self.logged_in:
                return
            current_username = self.username
        
        for msg in messages:
            sender = msg.get('sender')
            encrypted_content = msg.get('message')
            timestamp = msg.get('timestamp')

            with open('./errors/decryption.log', 'a') as f:
                f.write(f'Received message from {sender} at {timestamp}: {encrypted_content}\n')
            
            if not sender or not encrypted_content:
                continue
            
            # Get existing symmetric key with sender (don't establish new)
            symmetric_key = self._get_symmetric_key(sender)
            if not symmetric_key:
                # No key exists - skip this message (sender should have sent key first)
                with open('./errors/decryption.log', 'a') as f:
                    f.write(f'No symmetric key for {sender} at {timestamp}, skipping message\n')
                continue
            
            # Decrypt the message
            try:
                plaintext = self._decrypt_message(encrypted_content, symmetric_key)
                with open('./errors/decryption.log', 'a') as f:
                    f.write(f'Decrypted message from {sender} at {timestamp}: {plaintext}\n')
            except Exception as e:
                with open('./errors/decryption.log', 'a') as f:
                    f.write(f'Decryption failed for message from {sender} at {timestamp}: {e}\n')
                continue
            
            # Store in MessageStore
            self.message_store.save_message(
                username=current_username,
                contact_username=sender,
                sender=sender,
                recipient=current_username,
                message=plaintext,
                encrypted=False
            )
            
            # Trigger message received callback
            if self.on_message_received:
                self.on_message_received(sender, plaintext, timestamp)
    
    def get_message_history(self, contact_username: str):
        """
        Retrieve message history with a specific contact.
        
        Args:
            contact_username: The contact's username
            
        Returns:
            list: List of message dicts with keys: sender, recipient, message, timestamp
        """
        with self._state_lock:
            current_username = self.username
        
        return self.message_store.load_messages(current_username, contact_username)
    
    def is_logged_in(self) -> bool:
        return self.logged_in
