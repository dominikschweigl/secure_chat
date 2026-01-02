# secure_chat

A secure command-line chat application using **public-key** and **symmetric-key encryption**.

- **Backend:** FastAPI  
- **Messaging:** Apache Kafka (one message queue per user)

---

## Server API Endpoints

### Authentication

#### `POST /chat/register`
**Register a new user**

**Parameters**
- `name`
- `password`
- `pub-key`

**Returns**
- `success`  
- `error` if the username is already taken

---

#### `POST /chat/login`
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

#### `POST /chat/logout`
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

### Messaging

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
