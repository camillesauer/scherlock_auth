from fastapi import FastAPI
import pickle
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from crud import *
from model import *
from schema import *
from fastapi import Depends, FastAPI, HTTPException, status

#https://fastapi.tiangolo.com/tutorial/first-steps/

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/predict/{input}")
def predict(input: str):
    tfidf, model = pickle.load(open('model.bin', 'rb'))
    predictions = model.predict(tfidf.transform([input]))
    label = predictions[0]
    return {'text': input, 'label': label}

@app.get("/list")
async def userList():
    valret = []
    for x in fake_users_db:
        valret.append(x)
    return valret

@app.get("/enable/{user}")
async def enable(user, current_user: User = Depends(get_current_admin_user)):
    fake_users_db[user]["disabled"] = not fake_users_db[user]["disabled"]
    return 200

@app.get("/")
async def main():
    return "Hello World !"

