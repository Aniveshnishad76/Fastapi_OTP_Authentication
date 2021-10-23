from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()
metadata = Base.metadata


class Books(Base):
    __tablename__ = "Books"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    book_name = Column(String(200), index=True, nullable=True)


class User(Base):
    __tablename__ = "User"

    id = Column(Integer,  index=True, autoincrement=True)
    name = Column(String(200), index=True, nullable=True)
    number = Column(String(100), index=True, nullable=False)
    email = Column(String(250),primary_key=True, index=True)
    address = Column(String(250), index=True, nullable=False)
    password = Column(String(2500), index=True)

    userbook = relationship("BookwithUser", back_populates="owner")


class BookwithUser(Base):
    __tablename__ = "BookwithUser"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_email = Column(String(250), index=True)
    book_name = Column(String(250), index=True)
    owner_email = Column(String(250), ForeignKey("User.email"))

    owner = relationship("User", back_populates="userbook")


class Otp(Base):
    __tablename__ = "Otp"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(259), index=True)
    otp = Column(Integer, index=True, nullable=False)
    status = Column(String(259), index=True, default=True)


class Admin(Base):
    __tablename__ = "Admin"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(250), index=True, nullable=True)
    password = Column(String(2500), index=True)
