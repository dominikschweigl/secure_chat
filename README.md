# secure_chat

A secure command-line chat application using **public-key** and **symmetric-key encryption**.

- **Frontend** Textual CLI
- **Backend:** FastAPI
- **Messaging:** Apache Kafka (one message queue per user)

---

## TODO
- encrypt session-key in the request headers to the server
- logout endpoint gives unauthorized error

## Server API Endpoints

### Authentication

#### `POST /chat/auth/register`

**Register a new user**

**Parameters**

- `name`
- `password`
- `pub-key`

**Returns**

- `success`
- `error` if the username is already taken

---

#### `POST /chat/auth/login`

**Log in an existing user**

**Parameters**

- `name`
- `password`

**Returns**

- `session-key` (encrypted with the user's public key)
- `error` if:
  - password is incorrect
  - username does not exist

---

> All endpoints below require a valid session key

---

### Session Management

#### `POST /chat/auth/logout`

**Log out the user**

**Returns**

- Revokes the user’s session key

---

### Users & Presence

#### `GET /chat/users`

**List active users**

**Returns**

- List of currently registered/online users
- `error` if request fails

---

#### `POST /chat/presence/{username}`

**Update user presence**

**Description**

- Updates the online/offline status of the user

**Returns**

- `OK`
- `error`

---

### Key Exchange

#### `GET /chat/{username}/publickey`

**Initialize chat with a user**

**Returns**

- Target user’s public key
- `error` if user does not exist

---
#### `POST /chat/{username}/keyexchange`

**Exchange symmetric encryption key**

**Parameters**

- `encrypted_key` (symmetric key encrypted with recipient's RSA public key)

**Behavior**

- Allows sender to securely transmit a symmetric AES key to the recipient
- The symmetric key is used for encrypting subsequent messages
- Key is encrypted with the recipient's RSA public key to ensure confidentiality

**Returns**

- `OK`
- `error` if recipient does not exist or encryption fails

---
### Messaging

#### `GET /chat/messages`

**Retrieve messages from the user's queue**

- Connects to the user's dedicated Kafka topic (`user_queue_{username}`)
- Fetches all messages from the earliest available offset
- Retrieves both standard chat messages and system events

**Message Schema**
- `type`: Message category (e.g., `CHAT_MESSAGE`, `KEY_EXCHANGE`)
- `sender`: Username of the sender
- `message`: The encrypted payload
- `timestamp`: ISO-8601 formatted transmission time

**Returns**
- `messages`: An array of message objects

---

#### `POST /chat/{username}`

**Send a message to a user**

**Parameters**

- `message`

**Behavior**

- Automatically adds:
  - sender username
  - timestamp
- Pushes message into the recipient’s Kafka queue

**Returns**

- `OK`
- `error`

---

## Notes

- Each user has a dedicated Kafka message queue
- All sensitive communication is encrypted
- Session keys are required for all protected endpoints
