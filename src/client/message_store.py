import os
import json
from datetime import datetime
from typing import List, Dict, Optional


class MessageStore:
    """
    Manages storage of message history for users and their contacts.
    
    Directory structure:
    messages/
      {username}/
        {contact_name}.json  # Message history with this contact
    
    Each JSON file contains an array of message objects:
    [
      {
        "timestamp": "2026-01-04T10:30:00",
        "sender": "alice",
        "recipient": "bob",
        "message": "Hello!",
        "encrypted": false
      },
      ...
    ]
    """
    # File extension for message history
    MESSAGE_FILE_EXT = ".json"
    
    def __init__(self, directory: str = "messages"):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)
    
    def _get_user_dir(self, username: str) -> str:
        """Get the directory path for a specific user."""
        user_dir = os.path.join(self.directory, username)
        os.makedirs(user_dir, exist_ok=True)
        return user_dir
    
    def _get_message_file_path(self, username: str, contact_username: str) -> str:
        """Get the file path for messages with a specific contact."""
        user_dir = self._get_user_dir(username)
        return os.path.join(user_dir, f"{contact_username}{self.MESSAGE_FILE_EXT}")
    
    def save_message(self, username: str, contact_username: str, sender: str, 
                    recipient: str, message: str, encrypted: bool = False):
        """
        Save a message to the message history.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            sender: The message sender's username
            recipient: The message recipient's username
            message: The message content
            encrypted: Whether the message is encrypted
        """
        if not username or not contact_username:
            raise ValueError("Username or contact_username not set.")
        
        message_file = self._get_message_file_path(username, contact_username)
        
        # Load existing messages
        messages = self._load_messages_from_file(message_file)
        
        # Add new message
        message_entry = {
            "timestamp": datetime.now().isoformat(),
            "sender": sender,
            "recipient": recipient,
            "message": message,
            "encrypted": encrypted
        }
        messages.append(message_entry)
        
        # Save back to file
        with open(message_file, "w") as f:
            json.dump(messages, f, indent=2)
    
    def load_messages(self, username: str, contact_username: str) -> List[Dict]:
        """
        Load all messages with a specific contact.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            
        Returns:
            List[Dict]: List of message objects, empty list if no messages exist
        """
        message_file = self._get_message_file_path(username, contact_username)
        return self._load_messages_from_file(message_file)
    
    def _load_messages_from_file(self, file_path: str) -> List[Dict]:
        """Load messages from a JSON file."""
        if not os.path.exists(file_path):
            return []
        
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    
    def get_recent_messages(self, username: str, contact_username: str, 
                           limit: int = 50) -> List[Dict]:
        """
        Get the most recent messages with a contact.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            limit: Maximum number of messages to return
            
        Returns:
            List[Dict]: List of the most recent message objects
        """
        messages = self.load_messages(username, contact_username)
        return messages[-limit:] if messages else []
    
    def clear_messages(self, username: str, contact_username: str):
        """
        Clear all messages with a specific contact.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
        """
        message_file = self._get_message_file_path(username, contact_username)
        if os.path.exists(message_file):
            os.remove(message_file)
    
    def has_messages(self, username: str, contact_username: str) -> bool:
        """
        Check if there are any messages stored with a contact.
        
        Args:
            username: The current user's username
            contact_username: The contact's username
            
        Returns:
            bool: True if messages exist
        """
        message_file = self._get_message_file_path(username, contact_username)
        return os.path.exists(message_file) and len(self._load_messages_from_file(message_file)) > 0
    
    def get_all_contacts(self, username: str) -> List[str]:
        """
        Get list of all contacts that have message history.
        
        Args:
            username: The current user's username
            
        Returns:
            List[str]: List of contact usernames
        """
        user_dir = self._get_user_dir(username)
        contacts = []
        
        if os.path.exists(user_dir):
            for filename in os.listdir(user_dir):
                if filename.endswith(self.MESSAGE_FILE_EXT):
                    contact_name = filename[:-len(self.MESSAGE_FILE_EXT)]
                    contacts.append(contact_name)
        
        return sorted(contacts)
