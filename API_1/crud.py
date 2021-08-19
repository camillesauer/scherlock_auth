from api_routes import *
from fastapi.security import OAuth2PasswordBearer
from datetime import timedelta
from jose import jwt
from passlib.context import CryptContext
from schema import *
from sqlalchemy.orm import Session
import pyotp
from typing import List


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(User).offset(skip).limit(limit).all()


def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        username=user.username,
        hashed_password=hashed_password,
        otp_secret=pyotp.random_base32(),
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, db_user: User):
    db.delete(db_user)
    db.commit()
    return "Successfully deleted"


def update_user(db : Session, db_user: User, new_username: str):
    db_user.username = new_username
    db.commit()
    db.refresh(db_user)
    return "Successfully updated!"


def update_user_self(db: Session, current_user: User, user_update: UserUpdate):
    db_user = get_user(db, current_user.id)
    db_user.username = user_update.new_username
    db_user.hashed_password = pwd_context.hash(user_update.password)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_feeling(db: Session, message: MessageCreate, user_id: int):
    db_message = Message(description=message.description, user_id=user_id)
    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    return db_message


def get_feelings_by_user_id(db: Session, user_id: int):
    return db.query(Message).filter(Message.user_id == user_id).all()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, user_id: int):
    return db.get(User, user_id)


def authenticate_user(db, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
