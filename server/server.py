import json
import os
import secrets
import hashlib
import asyncio
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, status
from sqlalchemy import create_engine, Column, String, Boolean, Text
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
    is_online = Column(Boolean, default=False)
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

class PresenceUpdate(BaseModel):
    online: bool

app = FastAPI(title="Secure E2EE Chat Server")
producer: Optional[AIOKafkaProducer] = None

@app.on_event("startup")
async def startup_event():
    global producer
    await asyncio.sleep(2)
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
    await producer.start()

@app.on_event("shutdown")
async def shutdown_event():
    if producer: await producer.stop()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_current_user(
    x_session_key: Optional[str] = Header(None, alias="X-Session-Key"), 
    db: Session = Depends(get_db)
):
    if not x_session_key:
         raise HTTPException(status_code=401, detail="Session key missing")

    incoming_key_hash = hashlib.sha256(x_session_key.encode()).hexdigest()
    user = db.query(User).filter(User.session_key_hash == incoming_key_hash).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")
        
    return user

def ensure_kafka_topic(username: str):
    try:
        admin_client = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, client_id='admin')
        topic_name = f"user_queue_{username}"
        admin_client.create_topics([NewTopic(name=topic_name, num_partitions=1, replication_factor=1)])
        admin_client.close()
    except TopicAlreadyExistsError: pass
    except Exception: pass

@app.post("/chat/auth/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
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
def logout(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    current_user.session_key_hash = None
    current_user.is_online = False
    db.commit()
    return {"status": "OK"}

@app.get("/chat/messages")
async def get_messages(current_user: User = Depends(get_current_user)):
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

@app.post("/chat/{username}")
async def send_message(username: str, data: MessageSend, current_user: User = Depends(get_current_user)):
    topic = f"user_queue_{username}"
    payload = {
        "type": "CHAT_MESSAGE",
        "sender": current_user.username,
        "message": data.message,
        "timestamp": datetime.utcnow().isoformat()
    }
    await producer.send_and_wait(topic, json.dumps(payload).encode())
    return {"status": "OK"}

@app.post("/chat/presence/{username}")
def update_presence(
    username: str,
    data: PresenceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if username != current_user.username:
        raise HTTPException(status_code=403, detail="Cannot update other user's presence")

    current_user.is_online = data.online
    db.commit()
    return {"status": "OK"}

@app.get("/chat/users")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    users = db.query(User).all()
    return [{"username": u.username, "online": u.is_online} for u in users]

@app.post("/chat/{username}/keyexchange")
async def key_exchange(username: str, data: KeyExchange, current_user: User = Depends(get_current_user)):
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
def get_public_key(
    username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "public_key": user.public_key
    }