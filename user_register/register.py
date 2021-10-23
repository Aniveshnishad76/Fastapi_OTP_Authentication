import random

import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from fastapi_mail import ConnectionConfig, MessageSchema, FastMail
from sqlalchemy.orm import Session
from sqlalchemy.util import asyncio

import models
from database import SessionLocal
from user_register.schemas import UserRegister, UserRegisterOtp


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


router = APIRouter(
    prefix="/user",
    tags=['Users']
)

conf = ConnectionConfig(
    MAIL_USERNAME="anivesh.nishad07@gmail.com",
    MAIL_PASSWORD="9589957396@",
    MAIL_FROM="anivesh.nishad07@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_TLS=True,
    MAIL_SSL=False,
    USE_CREDENTIALS=True
)


def set_password(pw):
    pwhash = bcrypt.hashpw(pw.encode('utf8'), bcrypt.gensalt())
    password_hash = pwhash.decode('utf8')
    return password_hash


def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt())


def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


async def mail(user):
    otp = random.randint(10000, 99999)
    email = user.email
    template = """ FAST api OTP """ + str(otp) + """ is here."""
    message = MessageSchema(
        subject="Fastapi OTP",
        recipients=[email],  # List of recipients, as many as you can pass
        html=template,
        subtype="html"
    )

    fm = FastMail(conf)
    await fm.send_message(message)
    return otp


@router.post("/register")
def user_register(user: UserRegister, db: Session = Depends(get_db)):
    email = db.query(models.User).filter(models.User.email == user.email).first()
    number = db.query(models.User).filter(models.User.number == user.number).first()
    if email:
        return HTTPException(status_code=400, detail=" Email already exist")
    elif number:
        return HTTPException(status_code=400, detail=" Number already exist")
    else:
        otp = asyncio.run(mail(user))
        obj = models.Otp(email=user.email, otp=otp)
        db.add(obj)
        db.commit()
        db.refresh(obj)

        return "otp send successfully Please Enter OTP"
        # password = set_password(user.password)
        # obj = models.User(name=user.name, number=user.number, email=user.email, address=user.address, password=password)
        # db.add(obj)
        # db.commit()
        # db.refresh(obj)
        # return "user registered Successfully"


@router.post("/register_otp")
def user_register_otp(userotp: UserRegisterOtp, user: UserRegister, db: Session = Depends(get_db)):
    otp = db.query(models.Otp).filter(
        (models.Otp.email == userotp.email), (models.Otp.status == "true"), (models.Otp.otp == userotp.otp)).first()
    if otp is None:
        return HTTPException(status_code=400, detail="Invalid otp")
    else:
        otp1 = db.query(models.Otp).filter(
            (models.Otp.email == userotp.email), (models.Otp.status == "true")).first()
        setattr(otp1, 'status', 'false')
        password = set_password(user.password)
        obj = models.User(name=user.name, number=user.number, email=user.email, address=user.address, password=password)
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return "user registered Successfully"
