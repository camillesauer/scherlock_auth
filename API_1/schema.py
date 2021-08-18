from enum import Enum
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


class UserBase(BaseModel):
    pass


#class UserCreate(UserBase):
#    role: Role = Role.user
#    username: str
#    password: str


class UserUpdate(UserBase):
    password: str
    new_username: str
    id: int


class User(UserBase):
    id: int
    username: str
    disabled: bool = False

    class Config:
        orm_mode = True


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


class Role(str, Enum):
    admin = 'admin'
    user = 'user'


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


"""
class MessageBase(BaseModel):
    pass


class Message(MessageBase):
    id: int
    description: str
    user_id: int

    class Config:
        orm_mode = True
"""