from typing import List

from pydantic import BaseModel, EmailStr


class UserRegister(BaseModel):
    name: str
    number: str
    email: EmailStr
    address: str
    password: str

    class Config:
        orm_mode = True


class UserRegisterOtp(BaseModel):
    email: EmailStr
    otp: int

    class Config:
        orm_mode = True
