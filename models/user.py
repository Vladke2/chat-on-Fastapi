from datetime import datetime
from . import Base
from sqlalchemy import Column, String, Integer, Text, DateTime


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, index=True)
    # email = Column(String(50), nullable=True, unique=True)
    hashed_password = Column(String)
    # age = Column(String, nullable=False)
    # about_me = Column(Text, nullable=True)
    # last_seen = Column(DateTime(), default=datetime.utcnow)
