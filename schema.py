from pydantic import BaseModel, EmailStr


class UserList(BaseModel):
    id: int
    name: str
    number: str
    email: EmailStr
    address: str

    # password: str

    class Config:
        orm_mode = True

