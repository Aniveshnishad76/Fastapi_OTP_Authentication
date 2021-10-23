from pydantic import BaseModel


class AdminLogin(BaseModel):
    username: str
    password: str

    class Config:
        orm_mode = True


class AdminRegister(BaseModel):
    id: int
    username: str
    password: str

    class Config:
        orm_mode = True


class AdminProfile(BaseModel):
    id: int
    username: str
    password: str

    class Config:
        orm_mode = True


class UpdateAdmin(BaseModel):
    username: str

    class Config:
        orm_mode = True


class UpdateAdminPassword(BaseModel):
    username: str

    class Config:
        orm_mode = True


class AddBook(BaseModel):
    book_name: str

    class Config:
        orm_mode = True
