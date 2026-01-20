# secure_chat

A secure command-line chat application using **RSA (Public-Key)** and **AES (Symmetric-Key) encryption**.

- **Frontend:** Textual CLI
- **Backend:** FastAPI
- **Messaging:** Apache Kafka (dedicated queues per user for messages and keys)
- **Database:** SQLite (SQLAlchemy)

---

## Setup

### 1. Running the Server
2. Navigate to the server directory: `cd server`
1. Build the image: `docker-compose build`
2. Start the service: `docker-compose up`

### 2. Running the Client
1. In order for the client to run, the necessary Python dependencies inside the `requirements.txt` need to be installed first. Install them with: `pip install -r requirements.txt`
2. Then start the chat: `python3 tui.py` or `python tui.py`

> **Note**: It is recommended to use a python virtual environment for the client execution.

> **Note:** Multiple client interfaces can be executed in parallel. For that simply run `python tui.py` in a new terminal window and log in with a different user.

## Security Architecture

1. **Challenge-Response Auth:** Login and Registration use RSA-encrypted challenges to verify identity without sending raw passwords over the wire.
2. **HMAC Request Signing:** All protected endpoints require an `X-Request-Signature`. Requests are signed using a session key via HMAC-SHA256 to ensure integrity and prevent tampering.
3. **Replay Protection:** All signed requests must include an `X-Request-Timestamp` valid within a 30-second window.
4. **End-to-End Encryption (E2EE):** Chat messages are encrypted with symmetric AES keys, which are exchanged between users via RSA encryption.

---

## Server API Endpoints

### Authentication & Registration

#### `GET /chat/auth/register-challenge`
**Get registration requirements**
- **Returns:** Server's RSA public key and a unique registration nonce.

#### `POST /chat/auth/register`
**Register a new user**
- **Parameters:**
    - `username`
    - `public-key`: User's RSA public key.
    - `nonce`: The nonce from the challenge.
    - `payload`: Hex-encoded RSA bundle containing `hashed_password|nonce` (encrypted with Server's public key).

---

#### `POST /chat/auth/login-challenge`
**Phase 1 of Login**
- **Parameters:** `username`
- **Returns:** A challenge string encrypted with the **User's** public key.

#### `POST /chat/auth/login`
**Phase 2 of Login**
- **Parameters:** - `username`
    - `challenge_response`: The decrypted nonce from the challenge.
    - `proof`: HMAC-SHA256(nonce, password_hash).
- **Returns:** `session-key` (encrypted with the user's RSA public key).

---

> **Note:** All endpoints below require the following headers for HMAC verification:
> - `X-Request-Signature`: `HMAC_SHA256(session_key, "body|timestamp")`
> - `X-Request-Timestamp`: ISO-8601 string.

---

### Session Management

#### `POST /chat/auth/logout`
**Revoke session**
- **Returns:** Clears the active `session_key` for the user.

---

### Users & Presence

#### `GET /chat/users`
**List users**
- **Returns:** Array of users including their `online` status.

#### `POST /presence`
**Heartbeat**
- **Description:** Updates the `last_seen` timestamp for the authenticated user.

---

### Key Exchange (E2EE)

#### `GET /chat/{username}/publickey`
**Fetch recipient's key**
- **Returns:** The RSA public key of the target user.

#### `POST /chat/{username}/keyexchange`
**Send symmetric key**
- **Parameters:** `encrypted_key` (The AES key encrypted with the recipient's RSA public key).
- **Behavior:** Pushes the key to the recipient's dedicated key-exchange Kafka topic.

#### `GET /chat/keyexchange`
**Retrieve pending keys**
- **Returns:** List of encrypted symmetric keys sent to you by other users.

---

### Messaging

#### `GET /chat/messages`
**Retrieve chat messages**
- **Behavior:** Fetches all pending messages from the user's Kafka queue (`user_queue_{username}`).
- **Returns:** Array of message objects (sender, encrypted payload, timestamp).

#### `POST /chat/{username}/send`
**Send message**
- **Parameters:** `message` (The AES-encrypted ciphertext).
- **Behavior:** Routes the message to the recipient's Kafka queue.

---