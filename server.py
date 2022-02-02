# FastAPI Server
import base64
from hashlib import sha256
import hmac
import json
from typing import Optional
from os import getenv

from fastapi import FastAPI, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

# key for signing cookies (should be in enviroment variable instead of code)
SECRET_KEY = getenv('SECRET_KEY')
PASSWORD_SALT = getenv('PASSWORD_SALT')

def sign_data(data: str) -> str:
    """Return signed data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    return users[username]["password"].lower() == \
            sha256( (password + PASSWORD_SALT).encode() ).hexdigest().lower()

users = {
    "alexey@user.com":{
        "name": "Alexey",
        "password": "3eb1e4c97731a6c5d375debafc55544005a2210b5a663d30f5f303d5d366d9b1",
        "balance": 100_000
    },
    "petr@user.com":{
        "name": "Petr",
        "password": "8050a8df299814b51c87c45c0abe959847849f67a0a1effb404ebf34934c3418",
        "balance": 555_555
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)) -> Response():
    with open("./templates/login.html", 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Hello, {user['name']}!", media_type="text/html")
    
@app.post("/login")
def process_login_page(data: dict = Body(...)) -> Response():
    username = data["username"]
    password = data["password"]

    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
                json.dumps({
                    "success": False,
                    "message": "I don`t know you"
                }),
                media_type="application/json")
    
    response = Response(
                json.dumps({
                    "success": True,
                    "message": f"Hello, {user['name']}! <br/> Your balance is {user['balance']}"
                }),
                media_type="application/json")
    username_signed = f"{base64.b64encode(username.encode()).decode()}.{sign_data(username)}"
    response.set_cookie(key="username", value=username_signed)
    return response
