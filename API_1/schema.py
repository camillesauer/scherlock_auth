from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    id: int
    username: str
    disabled: bool = False

    class Config:
        orm_mode = True


class UserInDB(User):
    hashed_password: str


class Role(str, Enum):
    admin = 'admin'
    user = 'user'


class UserBase(BaseModel):
    pass


class UserCreate(UserBase):
    role: Role = Role.user
    username: str
    password: str


class UserUpdate(UserBase):
    password: str
    new_username: str
    id: int


class MessageBase(BaseModel):
    pass


class Message(MessageBase):
    id: int
    date: datetime
    description: str
    user_id: int

    class Config:
        orm_mode = True


class MessageCreate(MessageBase):
    description: str
