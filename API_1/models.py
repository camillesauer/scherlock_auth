from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Float, Enum, Text
from sqlalchemy.orm import relationship
from database import Base
from sqlalchemy.sql import func
from schemas import Role


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(20), unique=True, index=True)
    hashed_password = Column(String(100))
    otp_secret = Column(String(100))
    disabled = Column(Boolean, default=False)
    role = Column(Enum(Role))
