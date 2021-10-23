import bcrypt
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from admin.schemas import AdminLogin, AdminRegister, AdminProfile, UpdateAdmin, UpdateAdminPassword, AddBook
from database import SessionLocal
from user_register.schemas import UserRegister

app = FastAPI(
    prefix="/admin",
    tags=["Admin Actions"]
)
router = APIRouter(
    prefix="/admin",
    tags=["Admin Actions"]
)


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


def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


def set_password(pw):
    pwhash = bcrypt.hashpw(pw.encode('utf8'), bcrypt.gensalt())
    password_hash = pwhash.decode('utf8')
    return password_hash


@router.post("/adminlogin")
def admin_login(admin: AdminLogin, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    check_username = db.query(models.Admin).filter(models.Admin.username == admin.username).first()
    if check_username:
        password = check_password(admin.password, check_username.password)
        if password is True:
            access_token = Authorize.create_access_token(subject=admin.username)
            Authorize.set_access_cookies(access_token)
            return "Login Successfully"
        else:
            return HTTPException(status_code=400, detail="Password not matched with this username")

    else:
        return HTTPException(status_code=400, detail=" Invalid Details")


@router.post("/add_new_admin")
def add_new_admin(admin: AdminRegister, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_admin = Authorize.get_jwt_subject()
    if current_admin is None:
        return {"msg": "Please login to add new admin"}
    else:
        username = db.query(models.Admin).filter(models.Admin.username == admin.username).first()

        if username:
            return HTTPException(status_code=400, detail=" Username already exist")
        else:
            password = set_password(admin.password)
            obj = models.Admin(username=admin.username, password=password)
            db.add(obj)
            db.commit()
            db.refresh(obj)
            return "New Admin Registered Successfully"


@router.post("/add_user")
def add_user(user: UserRegister, db: Session = Depends(get_db)):
    email = db.query(models.User).filter(models.User.email == user.email).first()
    number = db.query(models.User).filter(models.User.number == user.number).first()
    if email:
        return HTTPException(status_code=400, detail=" Email already exist")
    elif number:
        return HTTPException(status_code=400, detail=" Number already exist")
    else:

        password = set_password(user.password)

        obj = models.User(name=user.name, number=user.number, email=user.email, address=user.address, password=password)
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return "user registered Successfully"


@router.post("/add_books")
def add_books(book: AddBook, db: Session = Depends(get_db)):
    book_name = db.query(models.Books).filter(models.Books.book_name == book.book_name).first()
    if book_name:
        return HTTPException(status_code=400, detail="Book already added")
    else:
        obj = models.Books(book_name=book.book_name)
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return "Book Added Successfully"


@router.get('/admin_profile', response_model=AdminProfile)
def admin(Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    Authorize.jwt_required()
    current_admin = Authorize.get_jwt_subject()
    if current_admin:
        admin = db.query(models.Admin).filter(models.Admin.username == current_admin).first()
        return admin


@router.delete('/admin_logout')
def admin_logout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    Authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@router.patch('/update_admin')
def update_user(user: UpdateAdmin, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_admin = Authorize.get_jwt_subject()
    all_data = db.query(models.Admin).filter(models.Admin.username == current_admin).first()

    if all_data is None:
        return {"message": "Admin not found"}
    else:
        update_data = user.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(all_data, key, value)
        db.commit()
        return {"message": "Admin Profile Update"}


@router.patch('/admin_update_password')
def update_user_password(admin: UpdateAdminPassword, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()

    all_data = db.query(models.Admin).filter(models.Admin.username == current_user).first()

    if all_data is None:
        return {"message": "Admin not found"}
    else:
        password = set_password(admin.password)
        setattr(all_data, 'password', password)
        db.commit()
        return {"message": "Admin password Update"}
