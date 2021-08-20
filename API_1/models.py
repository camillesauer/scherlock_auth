from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Enum
from sqlalchemy.orm import relationship
from database import Base
from sqlalchemy.sql import func
from schemas import Role


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(20), unique=True, index=True)
    hashed_password = Column(String(100))
    otp_secret = Column(String(100))
    disabled = Column(Boolean, default=False)
    role = Column(Enum(Role))
    messages = relationship("Message", backref="user")

class Message(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True, index=True)
    description = Column(String(100), index=True)
    date = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
