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
    key = RSA.generate(2048)
    return {
        "username": f"{name_prefix}_{secrets.token_hex(3)}",
        "password": "SecurePassword123!",
        "private_key": key,
        "public_key_pem": key.public_key().export_key().decode()
    }

def login_and_decrypt_session(user):
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

    @pytest.fixture(scope="class")
    def alice(self): return create_test_user("Alice")

    @pytest.fixture(scope="class")
    def bob(self): return create_test_user("Bob")

    # 1. Registration Tests
    def test_registration_flow(self, alice, bob):
        for user in [alice, bob]:
            logger.info(f"Registering {user['username']}...")
            payload = {
                "username": user["username"],
                "password": user["password"],
                "public-key": user["public_key_pem"]
            }
            resp = requests.post(f"{BASE_URL}/chat/auth/register", json=payload)
            assert resp.status_code == 200
        
        # Duplicate test
        resp_dup = requests.post(f"{BASE_URL}/chat/auth/register", json=payload)
        logger.info(f"Duplicate registration blocked: {resp_dup.status_code}")
        assert resp_dup.status_code == 400

    # 2. Login & Auth Tests
    def test_auth_and_session_security(self, alice):
        logger.info("Testing login and session decryption...")
        alice["session"] = login_and_decrypt_session(alice)
        assert len(alice["session"]) == 64

        # Verify X-Session-Key works
        headers = {"X-Session-Key": alice["session"]}
        resp = requests.get(f"{BASE_URL}/chat/users", headers=headers)
        assert resp.status_code == 200
        
        # Verify fake session key fails
        resp_fake = requests.get(f"{BASE_URL}/chat/users", headers={"X-Session-Key": "fake"})
        assert resp_fake.status_code == 401

    # 3. Communication Test (E2E Loop)
    def test_message_delivery_alice_to_bob(self, alice, bob):
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
        """Verify that multiple messages arrive in the correct sequence."""
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
        logger.info("Testing logout...")
        
        headers = {"X-Session-Key": alice["session"]}
        
        logout_resp = requests.post(f"{BASE_URL}/chat/auth/logout", headers=headers)
        
        assert logout_resp.status_code == 200
        
        # Short sleep to ensure DB write-lock is released
        time.sleep(0.1)
        
        # Post-logout request: This should now return 401
        resp = requests.get(f"{BASE_URL}/chat/users", headers=headers)
        assert resp.status_code == 401
        logger.info("Logout verified: Session key no longer active.")