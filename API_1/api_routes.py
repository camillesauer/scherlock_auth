from typing import List
from sqlalchemy.orm import Session
import crud, models, schemas
from database import SessionLocal, engine
from datetime import timedelta
from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordRequestForm
from crud import create_access_token
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from crud import ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
from fastapi.middleware.cors import CORSMiddleware
import database


models.Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    """
     Permit to verify if the person who want to connect has an account
      """
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
        token_data = schemas.TokenData(username=username)
        print(token_data)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: models.User = Depends(get_current_user)):
    """
      User Status
      """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_admin_user(admin_user: models.User = Depends(get_current_active_user)):
    """
      Admin Status
      """
    if admin_user.role == 'admin':
        return admin_user
    raise HTTPException(status_code=400, detail="User not admin!")


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
      Creating a user account.
      Access: For any people
      """
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="User already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    """
      Get users informations.
      Access: Only for administrator
      """
    if admin:
        users = crud.get_users(db, skip=skip, limit=limit)
        return users
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    """
      Get users informations by user_id
      Access: Only for administrator
      """
    if admin:
        db_user = crud.get_user(db, user_id=user_id)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return db_user
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")

@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    """
      Delete a user account.
      Access: Only for administrator
      """
    if admin:
        db_user = crud.get_user(db, user_id=user_id)
        if db_user:
            return crud.delete_user(db, db_user)
        else:
            raise HTTPException(status_code=404, detail="User not found")
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")


@app.patch("/users/", response_model=str)
def update_user(user: schemas.UserUpdate, db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    """
      Update users informations.
      Access: Only for administrator
      """
    if admin:
        db_user = crud.get_user(db=db, user_id=user.id)
        if db_user:
            return crud.update_user(db, db_user, user.new_username)
        else:
            raise HTTPException(status_code=404, detail="User not found")
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")



@app.patch("/users/me", response_model=str)
def update_my_info(user: schemas.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    """
    Update informations of my profile.
    Access: Only of the user who's connected
    """
    return crud.update_user(db, user.new_username)


@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
      Login to my profile.
      Access: For users who have an account
      """
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


@app.post("/messages", response_model=schemas.Message)
def create_message(message: schemas.MessageCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    """
      POST a message.
      Access: Only of the user who's connected
      """
    return crud.create_message(db, message, current_user.id)


@app.get("/messages", response_model=List[schemas.Message])
def read_all_messages(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    """
      Get all the messages a user posted
      Access: Only of the user who's connected
      """
    if current_user:
        db_message = crud.get_messages_by_user_id(db, user_id=current_user.id)
        if db_message is None:
            raise HTTPException(status_code=404, detail="Message not found")
        return db_message
    else:
        raise HTTPException(status_code=403, detail="Operation not permitted")