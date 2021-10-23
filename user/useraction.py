from typing import List

import bcrypt
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import SessionLocal
from user.schemas import UserLogin, Profile, UpdateUser, UpdateUserPassword, Books, UserEmail
from user_register.register import set_password
from user_register.schemas import UserRegister

app = FastAPI(
    prefix="/user",
    tags=["User Action"]
)
router = APIRouter(
    prefix="/user",
    tags=["User Action"]
)


def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_token_location: set = {"cookies"}
    authjwt_cookie_csrf_protect: bool = False


@AuthJWT.load_config
def get_config():
    return Settings()


@router.post("/login")
def user_login(user: UserLogin, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    check_email = db.query(models.User).filter(models.User.email == user.email).first()
    print(check_email)
    if check_email:
        password = check_password(user.password, check_email.password)
        if password is True:
            access_token = Authorize.create_access_token(subject=user.email)
            Authorize.set_access_cookies(access_token)
            return "Login Successfully"
        else:
            return HTTPException(status_code=400, detail="Password not matched with this email")

    else:
        return HTTPException(status_code=400, detail="User Invalid")


@router.post("/buy_book")
def buy_book(books: Books, user: UserEmail, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    # books = db.query(models.Books).all()
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()

    if current_user:
        check_book = db.query(models.Books).filter(models.Books.book_name == books.book_name).first()
        if check_book is None:
            return HTTPException(status_code=400, detail="Book not Found")
        else:
            check_user_book = db.query(models.BookwithUser).filter((models.BookwithUser.owner_email == current_user),(models.BookwithUser.book_name == books.book_name)).first()
            if check_user_book:
                return "Already added Book to this user"
            else:
                obj = models.BookwithUser(owner_email=user.user_email, book_name=books.book_name)
                db.add(obj)
                db.commit()
                db.refresh(obj)
                return "Book Buy Successfully"
    else:
        return "Please Login"


@router.get("/home")
def user_home(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return f"Welcome {current_user}"


@router.get('/profile', response_model=Profile)
def user(Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    print(current_user)
    if current_user:
        user = db.query(models.User).filter(models.User.email == current_user).first()
        return user


@router.delete('/logout')
def logout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    Authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@router.patch('/update_user')
def update_user(user: UpdateUser, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()

    all_data = db.query(models.User).filter(models.User.email == current_user).first()

    if all_data is None:
        return {"message": "User not found"}
    else:
        update_data = user.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(all_data, key, value)
        db.commit()
        return {"message": "User Profile Update"}


@router.patch('/user_update_password')
def update_user_password(user: UpdateUserPassword, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()

    all_data = db.query(models.User).filter(models.User.email == current_user).first()

    if all_data is None:
        return {"message": "User not found"}
    else:
        password = set_password(user.password)
        setattr(all_data, 'password', password)
        db.commit()
        return {"message": "User password Update"}
