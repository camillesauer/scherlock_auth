import schema
from database import SessionLocal
from sqlalchemy.orm import Session
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from crud import oauth2_scheme, create_access_token, timedelta
from model import User, Message
from jose import JWTError, jwt
from typing import List
import model
from database import engine
import crud


model.Base.metadata.create_all(bind=engine)

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "8e7ada9de019136b0cd1a35ae9803c68644ae59829ab388cd681920773d0b127"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


app = FastAPI()


@app.get("/")
def hello():
    return {"message": "Bienvenue dans ma super API"}


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schema.TokenData(username=username)
        print(token_data)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_admin_user(admin_user: User = Depends(get_current_active_user)):
    if admin_user.role == 'admin':
        return admin_user
    raise HTTPException(status_code=400, detail="User not admin!")


@app.post("/users/", response_model=schema.User)
def create_user(user: schema.UserCreate, db: Session = Depends(get_db)):
    """
    I create a user
    """
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="User already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model= List[schema.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    if admin:
        users = crud.get_users(db, skip=skip, limit=limit)
        return users
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")


@app.get("/users/{user_id}", response_model=schema.User)
def read_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    if admin:
        db_user = crud.get_user(db, user_id=user_id)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return db_user
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")


@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    if admin:
        db_user = crud.get_user(db, user_id=user_id)
        if db_user:
            return crud.delete_user(db, db_user)
        else:
            raise HTTPException(status_code=404, detail="User not found")
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")


@app.patch("/users/", response_model=str)
def update_user(user: schema.UserUpdate, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    if admin:
        db_user = crud.get_user(db=db, user_id=user.id)
        if db_user:
            return crud.update_user(db, db_user, user.new_username)
        else:
            raise HTTPException(status_code=404, detail="User not found")
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")


@app.patch("/users/me", response_model=str)
def update_my_info(user: schema.UserUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    return crud.update_user(db, user.new_username)


@app.post("/messages", response_model=schema.MessageBase)
def create_message(message: schema.MessageCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    return crud.create_message(db, message, current_user.id)

"""
@app.get("/messages", response_model=List[schema.MessageBase])
def read_all_messages(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user:
        db_message = crud.get_messages_by_user_id(db, user_id=current_user.id)
        if db_message is None:
            raise HTTPException(status_code=404, detail="Message not found")
        return db_message
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")
"""

@app.post("/login", response_model=schema.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}