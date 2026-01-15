import json
import os
import secrets
import hashlib
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, status
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, Field
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer, TopicPartition
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import TopicAlreadyExistsError

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from passlib.context import CryptContext

# --- Configuration ---
DB_DIR = "data"
DB_NAME = "server.db"
DATABASE_URL = f"sqlite:///./{DB_DIR}/{DB_NAME}"
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_URL", "kafka:9092")

if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    password_hash = Column(String)
    public_key = Column(Text)
    last_seen = Column(DateTime, nullable=True)
    session_key_hash = Column(String, nullable=True, index=True)

Base.metadata.create_all(bind=engine)

class UserRegister(BaseModel):
    username: str
    password: str
    public_key: str = Field(..., alias="public-key")
    class Config: populate_by_name = True

class UserLogin(BaseModel):
    username: str
    password: str

class MessageSend(BaseModel):
    message: str 

class KeyExchange(BaseModel):
    encrypted_key: str

app = FastAPI(title="Secure E2EE Chat Server")
producer: Optional[AIOKafkaProducer] = None

@app.on_event("startup")
async def startup_event():
    """
    FastAPI startup event.
    
    Initializes the global Kafka producer. Waits 2 seconds to allow Kafka service to start.
    """
    global producer
    await asyncio.sleep(2)
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
    await producer.start()


@app.on_event("shutdown")
async def shutdown_event():
    """
    FastAPI shutdown event.

    Stops the global Kafka producer cleanly to release resources.
    """
    if producer:
        await producer.stop()


def get_db():
    """
    Provides a SQLAlchemy database session for dependency injection.

    Yields:
        Session: SQLAlchemy session object.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(
    x_session_key: Optional[str] = Header(None, alias="X-Session-Key"), 
    db: Session = Depends(get_db)
):
    """
    Dependency to authenticate the user via session key.

    Args:
        x_session_key (str): Session key sent in request header.
        db (Session): Database session.

    Returns:
        User: Authenticated user.

    Raises:
        HTTPException 401: If session key is missing or invalid.
    """
    if not x_session_key:
        raise HTTPException(status_code=401, detail="Session key missing")

    incoming_key_hash = hashlib.sha256(x_session_key.encode()).hexdigest()
    user = db.query(User).filter(User.session_key_hash == incoming_key_hash).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")
    return user


def ensure_kafka_topic(username: str):
    """
    Ensures a Kafka topic exists for a user.

    Args:
        username (str): The username to create a topic for.

    Notes:
        Silently ignores errors if the topic already exists.
    """
    try:
        admin_client = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, client_id='admin')
        topic_name = f"user_queue_{username}"
        admin_client.create_topics([NewTopic(name=topic_name, num_partitions=1, replication_factor=1)])
        admin_client.close()
    except TopicAlreadyExistsError:
        pass
    except Exception:
        pass


@app.post("/chat/auth/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Registers a new user.

    Args:
        user_data (UserRegister): Username, password, and public key.
        db (Session): Database session.

    Returns:
        dict: {"status": "success"} on success.

    Raises:
        HTTPException 400: If username is already taken.
    """
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username taken")
    new_user = User(
        username=user_data.username,
        password_hash=pwd_context.hash(user_data.password),
        public_key=user_data.public_key
    )
    db.add(new_user)
    db.commit()
    ensure_kafka_topic(user_data.username)
    return {"status": "success"}


@app.post("/chat/auth/login")
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates a user and generates a session key.

    Args:
        user_data (UserLogin): Username and password.
        db (Session): Database session.

    Returns:
        dict: {"session-key": <RSA-encrypted session key>}

    Notes:
        The session key must be used in the X-Session-Key header for future requests.

    Raises:
        HTTPException 401: If credentials are invalid.
    """
    print("Login attempt for user:", user_data.username)
    print("password:", user_data.password)
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not pwd_context.verify(user_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    raw_key = secrets.token_hex(32)
    user.session_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    user.is_online = True
    db.commit()
    db.refresh(user)
    recipient_key = RSA.import_key(user.public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
    return {"session-key": cipher_rsa.encrypt(raw_key.encode()).hex()}


@app.post("/chat/auth/logout") 
def logout(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Logs out the current user.

    Clears the session key and sets the user offline.

    Args:
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: {"status": "OK"}
    """
    current_user.session_key_hash = None
    current_user.is_online = False
    db.commit()
    return {"status": "OK"}


@app.get("/chat/messages")
async def get_messages(current_user: User = Depends(get_current_user)):
    """
    Retrieves all messages for the authenticated user from Kafka.

    Args:
        current_user (User): Authenticated user.

    Returns:
        dict: {"messages": [<list_of_messages>]}
    """
    topic = f"user_queue_{current_user.username}"
    consumer = AIOKafkaConsumer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        auto_offset_reset='earliest',
        enable_auto_commit=False
    )
    messages = []
    try:
        await consumer.start()
        tp = TopicPartition(topic, 0)
        consumer.assign([tp])
        await consumer.seek_to_beginning(tp)
        data = await consumer.getmany(timeout_ms=1000)
        for tp_key, msgs in data.items():
            for msg in msgs:
                messages.append(json.loads(msg.value.decode()))
    except Exception as e:
        print(f"Polling error: {e}")
    finally:
        await consumer.stop()
    return {"messages": messages}


@app.post("/chat/{username}/send")
async def send_message(username: str, data: MessageSend, current_user: User = Depends(get_current_user)):
    """
    Sends a chat message to a specific user.

    Args:
        username (str): Recipient username.
        data (MessageSend): Message content.
        current_user (User): Authenticated sender.

    Returns:
        dict: {"status": "OK"}
    """
    topic = f"user_queue_{username}"
    payload = {
        "type": "CHAT_MESSAGE",
        "sender": current_user.username,
        "message": data.message,
        "timestamp": datetime.utcnow().isoformat()
    }
    await producer.send_and_wait(topic, json.dumps(payload).encode())
    return {"status": "OK"}


@app.post("/presence")
def update_presence(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Updates the online/offline presence of the authenticated user.

    Args:
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: {"status": "OK"}
    """
    current_user.last_seen = datetime.utcnow()
    db.commit()
    return {"status": "OK"}


@app.get("/chat/users")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Lists all registered users and their online status.

    Args:
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        list: [{"username": str, "online": bool}]
    """
    users: List[User] = db.query(User).all()
    return [
        {
            "username": u.username, 
            "online": u.last_seen and u.last_seen > datetime.utcnow() - timedelta(seconds=15)
        } for u in users
    ]


@app.post("/chat/{username}/keyexchange")
async def key_exchange(username: str, data: KeyExchange, current_user: User = Depends(get_current_user)):
    """
    Sends an encrypted key to another user for E2EE.

    Args:
        username (str): Recipient username.
        data (KeyExchange): {"encrypted_key": str}.
        current_user (User): Authenticated sender.

    Returns:
        dict: {"status": "OK"}
    """
    topic = f"user_queue_{username}"
    payload = {
        "type": "KEY_EXCHANGE",
        "sender": current_user.username,
        "encrypted_key": data.encrypted_key,
        "timestamp": datetime.utcnow().isoformat()
    }
    await producer.send_and_wait(topic, json.dumps(payload).encode())
    return {"status": "OK"}


@app.get("/chat/{username}/publickey")
async def get_public_key(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Retrieves the public key of a target user for E2EE initialization.

    Args:
        username (str): Target username.
        db (Session): Database session.
        current_user (User): Authenticated requester.

    Returns:
        dict: {"public_key": str}

    Raises:
        HTTPException 404: If the target user does not exist.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"public_key": user.public_key}
