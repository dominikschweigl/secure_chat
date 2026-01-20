import os
from Crypto.PublicKey import RSA

class KeyStore:
    """
    Manages storage of RSA keys for the user and their contacts.
    
    Directory structure:
    keys/
      {username}/
        private.pem      # User's own private key
        public.pem       # User's own public key
        contacts/
          {recipient_name}/
            public.pem     # Contact's RSA public key
            symmetric.key  # Symmetric AES key for this contact
    """

    PRIVATE_KEY_FILE = "private.pem"
    PUBLIC_KEY_FILE = "public.pem"
    SYMMETRIC_KEY_FILE = "symmetric.key"
    
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
    
    def _get_contact_dir(self, username: str, contact_username: str) -> str:
        """Get the directory path for a specific contact."""
        contact_dir = os.path.join(self._get_contacts_dir(username), contact_username)
        os.makedirs(contact_dir, exist_ok=True)
        return contact_dir

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
        private_key_path = os.path.join(user_dir, self.PRIVATE_KEY_FILE)
        
        with open(private_key_path, "w") as f:
            f.write(rsa_key.export_key().decode("utf-8"))
        
        # Also save public key for convenience
        public_key_path = os.path.join(user_dir, self.PUBLIC_KEY_FILE)
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
        private_key_path = os.path.join(user_dir, self.PRIVATE_KEY_FILE)
        
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
        
        contact_dir = self._get_contact_dir(username, contact_username)
        contact_key_path = os.path.join(contact_dir, self.PUBLIC_KEY_FILE)
        
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
        contact_dir = self._get_contact_dir(username, contact_username)
        contact_key_path = os.path.join(contact_dir, self.PUBLIC_KEY_FILE)
        
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
        contact_dir = self._get_contact_dir(username, contact_username)
        contact_key_path = os.path.join(contact_dir, self.PUBLIC_KEY_FILE)
        return os.path.exists(contact_key_path)
    
    def save_symmetric_key(self, username: str, contact_username: str, symmetric_key: bytes):
        """
        Save a symmetric encryption key for a contact.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            symmetric_key: The AES symmetric key (32 bytes)
        """
        if not symmetric_key or not username or not contact_username:
            raise ValueError("Symmetric key, username, or contact_username not set.")
        
        contact_dir = self._get_contact_dir(username, contact_username)
        symmetric_key_path = os.path.join(contact_dir, self.SYMMETRIC_KEY_FILE)
        
        with open(symmetric_key_path, "wb") as f:
            f.write(symmetric_key)
    
    def load_symmetric_key(self, username: str, contact_username: str) -> bytes | None:
        """
        Load a symmetric encryption key for a contact if it exists.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            
        Returns:
            bytes | None: The symmetric key or None if not found
        """
        contact_dir = self._get_contact_dir(username, contact_username)
        symmetric_key_path = os.path.join(contact_dir, self.SYMMETRIC_KEY_FILE)
        
        if not os.path.exists(symmetric_key_path):
            return None
        
        with open(symmetric_key_path, "rb") as f:
            return f.read()
    
    def has_symmetric_key(self, username: str, contact_username: str) -> bool:
        """
        Check if a symmetric key is stored for a contact.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            
        Returns:
            bool: True if the symmetric key exists
        """
        contact_dir = self._get_contact_dir(username, contact_username)
        symmetric_key_path = os.path.join(contact_dir, self.SYMMETRIC_KEY_FILE)
        return os.path.exists(symmetric_key_path)