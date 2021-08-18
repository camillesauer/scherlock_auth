from sqlalchemy import Boolean, Column, Integer, String, Enum
from sqlalchemy.orm import relationship
from database import Base
from sqlalchemy.sql import func
from schema import Role

"""
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(20), unique=True, index=True)
    hashed_password = Column(String(100))
    otp_secret = Column(String(100))
    disabled = Column(Boolean, default=False)
    role = Column(Enum(Role))

    items_message = relationship("Message", back_populates="message")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    description = Column(String(100), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    message = relationship("User", back_populates="items_message")
"""