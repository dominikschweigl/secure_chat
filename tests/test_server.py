import pytest
import requests
import base64
import logging
import time
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:8000"

# --- Helper Functions ---
def create_test_user(name_prefix):
    """
    Generates a test user with a fresh RSA key pair.

    Args:
        name_prefix (str): Prefix for username to ensure uniqueness.

    Returns:
        dict: Contains username, password, private_key, and public_key_pem.
    """
    key = RSA.generate(2048)
    return {
        "username": f"{name_prefix}_{secrets.token_hex(3)}",
        "password": "SecurePassword123!",
        "private_key": key,
        "public_key_pem": key.public_key().export_key().decode()
    }


def login_and_decrypt_session(user):
    """
    Logs in a test user and decrypts the session key.

    Args:
        user (dict): User dictionary containing username and private_key.

    Returns:
        str: Decrypted session key.

    Raises:
        Exception: If login fails.
    """
    payload = {"username": user["username"], "password": user["password"]}
    response = requests.post(f"{BASE_URL}/chat/auth/login", json=payload)
    if response.status_code != 200:
        raise Exception(f"Login failed: {response.text}")
    
    encrypted_hex = response.json()["session-key"]
    cipher_rsa = PKCS1_OAEP.new(user["private_key"], hashAlgo=SHA256)
    decrypted_bytes = cipher_rsa.decrypt(bytes.fromhex(encrypted_hex))
    return decrypted_bytes.decode('utf-8')


# --- Test Suite ---
class TestExtensiveServer:
    """
    Extensive integration test suite for the Secure E2EE Chat Server.

    Tests registration, authentication, message delivery, key exchange,
    message ordering, and session/logout handling.
    """

    @pytest.fixture(scope="class")
    def alice(self):
        """Fixture for a test user named Alice."""
        return create_test_user("Alice")

    @pytest.fixture(scope="class")
    def bob(self):
        """Fixture for a test user named Bob."""
        return create_test_user("Bob")

    # 1. Registration Tests
    def test_registration_flow(self, alice, bob):
        """
        Validates registration endpoint:

        - Successful registration of new users
        - Blocking duplicate registration with same username
        """
        for user in [alice, bob]:
            logger.info(f"Registering {user['username']}...")
            payload = {
                "username": user["username"],
                "password": user["password"],
                "public-key": user["public_key_pem"]
            }
            resp = requests.post(f"{BASE_URL}/chat/auth/register", json=payload)
            assert resp.status_code == 200

        # Duplicate registration attempt
        resp_dup = requests.post(f"{BASE_URL}/chat/auth/register", json=payload)
        logger.info(f"Duplicate registration blocked: {resp_dup.status_code}")
        assert resp_dup.status_code == 400

    # 2. Login & Auth Tests
    def test_auth_and_session_security(self, alice):
        """
        Tests login, session key decryption, and header-based authentication:

        - Valid login produces a session key
        - Requests using valid X-Session-Key succeed
        - Requests using invalid session key fail
        """
        logger.info("Testing login and session decryption...")
        alice["session"] = login_and_decrypt_session(alice)
        assert len(alice["session"]) == 64

        headers = {"X-Session-Key": alice["session"]}
        resp = requests.get(f"{BASE_URL}/chat/users", headers=headers)
        assert resp.status_code == 200

        resp_fake = requests.get(f"{BASE_URL}/chat/users", headers={"X-Session-Key": "fake"})
        assert resp_fake.status_code == 401

    # 3. Communication Test (E2E Loop)
    def test_message_delivery_alice_to_bob(self, alice, bob):
        """
        Verifies end-to-end message delivery:

        - Alice sends a message to Bob
        - Bob polls messages and receives Alice's message
        """
        bob["session"] = login_and_decrypt_session(bob)
        message_content = "Secret message for Bob's eyes only"
        logger.info(f"Alice sending message to {bob['username']}...")

        headers_alice = {"X-Session-Key": alice["session"]}
        send_resp = requests.post(
            f"{BASE_URL}/chat/{bob['username']}", 
            json={"message": message_content}, 
            headers=headers_alice
        )
        assert send_resp.status_code == 200

        # Wait for Kafka processing
        logger.info("Waiting for Kafka processing...")
        time.sleep(2)

        logger.info(f"Bob polling his inbox...")
        headers_bob = {"X-Session-Key": bob["session"]}
        recv_resp = requests.get(f"{BASE_URL}/chat/messages", headers=headers_bob)
        assert recv_resp.status_code == 200

        messages = recv_resp.json().get("messages", [])
        alice_msgs = [m for m in messages if m["sender"] == alice["username"]]
        assert len(alice_msgs) > 0
        assert alice_msgs[-1]["message"] == message_content
        logger.info("Success: Bob received the correct message from Alice!")

    def test_message_ordering(self, alice, bob):
        """
        Verifies multiple messages maintain correct chronological order.

        - Alice sends 5 sequential messages to Bob
        - Bob receives them in exact sent order
        """
        headers_alice = {"X-Session-Key": alice["session"]}
        headers_bob = {"X-Session-Key": bob["session"]}
        sent_messages = [f"Message Number {i}" for i in range(1, 6)]

        logger.info(f"Alice sending {len(sent_messages)} sequential messages...")
        for msg in sent_messages:
            requests.post(
                f"{BASE_URL}/chat/{bob['username']}", 
                json={"message": msg}, 
                headers=headers_alice
            )

        time.sleep(2)

        logger.info("Bob retrieving messages to verify order...")
        resp = requests.get(f"{BASE_URL}/chat/messages", headers=headers_bob)
        received_payloads = resp.json().get("messages", [])
        received_texts = [m["message"] for m in received_payloads if m["sender"] == alice["username"]]

        assert sent_messages == received_texts[-5:], "Messages arrived out of order!"
        logger.info("SUCCESS: All messages arrived in the exact order they were sent.")

    # 4. Key Exchange Test
    def test_key_exchange_logic(self, alice, bob):
        """
        Validates key exchange endpoint for E2EE:

        - Alice sends a fake encrypted key to Bob
        - Endpoint returns 200 OK
        """
        headers_alice = {"X-Session-Key": alice["session"]}
        fake_encrypted_key = base64.b64encode(b"session-aes-key").decode()

        logger.info("Testing Key Exchange endpoint...")
        resp = requests.post(
            f"{BASE_URL}/chat/{bob['username']}/keyexchange",
            json={"encrypted_key": fake_encrypted_key},
            headers=headers_alice
        )
        assert resp.status_code == 200

    # 5. Cleanup / Logout Test
    def test_logout_revocation(self, alice):
        """
        Tests logout and session revocation:

        - User logs out
        - Session key is invalidated
        - Subsequent requests with same session key fail
        """
        logger.info("Testing logout...")
        headers = {"X-Session-Key": alice["session"]}

        logout_resp = requests.post(f"{BASE_URL}/chat/auth/logout", headers=headers)
        assert logout_resp.status_code == 200

        # Ensure DB commit
        time.sleep(0.1)

        # Post-logout request should fail
        resp = requests.get(f"{BASE_URL}/chat/users", headers=headers)
        assert resp.status_code == 401
        logger.info("Logout verified: Session key no longer active.")
