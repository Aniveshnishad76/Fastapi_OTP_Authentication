from typing import List

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

import admin.adminaction
import models
import user.useraction
import user_register.register
from database import SessionLocal
from user_register.schemas import UserRegister

app = FastAPI()

app.include_router(user_register.register.router)
app.include_router(user.useraction.router)
app.include_router(admin.adminaction.router)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/all_user/", response_model=List[UserRegister])
def all_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return users


@app.get("/")
def index():
    return {"Home-Page": "Welcome to Home Page"}
