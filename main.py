from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse
import database
import actions
from typing import Optional

app = FastAPI()
db = database.get_db()
NO_AUTH_ENDPOINTS = [
    "^\/user\/login\/$",
    "^\/user\/register\/$",
    "^\/user\/verification\/$",

    # For Development
    "\/docs",
    "\/openapi.json"
] # REGEX

### MIDDLEWARES ###
@app.middleware("http")
async def authenticate(request: Request, call_next):
    token = request.query_params.get("token")
    if not actions.matching_regex_in_list(NO_AUTH_ENDPOINTS, request.url.path): # NOT FOR UNAUTHORIZED ACCESS
        # Check authentication
        if token == None:
            response = JSONResponse(content={"error": "Unauthorized!"}, status_code=401)
        else:
            user = database.get_user_by_token(token=token, db=database.get_db())
            if user == None:
                response = JSONResponse(content={"error": "Unauthorized!"}, status_code=401)
            elif user["is_active"] == 0:
                response = JSONResponse(content={"error": "User is not active!"}, status_code=400)
            else:
                request.state._user = user # Put user data into request for easy access
                response = await call_next(request)
    else:
        response = await call_next(request)
    return response

### ROUTES ###
@app.post("/user/register/")
async def register(username: str, password: str, email: str, request: Request):
    # Check password strength
    if not actions.check_password_strength(password):
        return JSONResponse(content={"error": "Password is too weak!"}, status_code=400)
    # Check email validity
    if not actions.is_email_valid(email):
        return JSONResponse(content={"error": "Invalid email!"}, status_code=400)
    # Check if user exists (with username or email)
    if database.get_user_by_username(username, db) is not None:
        return JSONResponse(content={"error": "Username is already taken!"}, status_code=400)
    if database.get_user_by_email(email, db) is not None:
        return JSONResponse(content={"error": "Email is already taken!"}, status_code=400)
    
    hashed_password = actions.hash_password(password)
    
    user = database.create_user(username, email, hashed_password, db)

    # Generate verification key
    verification_key = actions.generate_random_text()
    database.create_verification_key(user["id"], verification_key, db)

    # SEND EMAIL HERE

    return {"username": user["username"]}
@app.post("/user/login/")
async def login(username: str, password: str, request: Request):
    user = database.get_user_by_username(username, db)
    hashed_password = actions.hash_password(password)
    if user is None: return JSONResponse(content={"error": "User not found!"}, status_code=404)
    if user["password"] != hashed_password: return JSONResponse(content={"error": "Invalid password!"}, status_code=400)
    if user["is_active"] == 0: return JSONResponse(content={"error": "User is not active!"}, status_code=400)
    if user["token"] == None: return JSONResponse(content={"error": "User is not verified!"}, status_code=400)
    return {"token": user["token"], "username": user["username"]}
@app.post("/user/verification/")
async def verify(key: str, username: str, request: Request):
    user = database.get_user_by_username(username, db)
    verification_key = database.get_verification_key(user_id=user["id"], db=db)
    
    if verification_key is None: return JSONResponse(content={"error": "User is already verified!"}, status_code=400)
    if verification_key != key: return JSONResponse(content={"error": "Invalid verification key!"}, status_code=400)

    new_token = actions.generate_token(user_id=user["id"])
    database.change_token(user_id=user["id"], token=new_token, db=db)
    database.delete_verification_key(user_id=user["id"], db=db)

    return {"username": user["username"]}

@app.post("/user/me/")
async def me(request: Request):
    return {"username": request.state._user["username"]}

@app.post("/user/delete/")
async def delete(request: Request):
    # database.delete_user(request.state._user["id"], db) # NOT RECOMMENDED
    database.deactivate_user(request.state._user["id"], db) # RECOMMENDED
    return {"message": "User deleted!"}
@app.post("/user/update/")
async def update(request: Request, password: Optional[str] = Form(None), email: Optional[str] = Form(None)):
    changes = {}
    if password is not None:
        if not actions.check_password_strength(password):
            return JSONResponse(content={"error": "Password is too weak!"}, status_code=400)
        changes["password"] = actions.hash_password(password)
    if email is not None:
        if not actions.is_email_valid(email):
            return JSONResponse(content={"error": "Invalid email!"}, status_code=400)
        if database.get_user_by_email(email, db) is not None:
            return JSONResponse(content={"error": "Email is already taken!"}, status_code=400)
        changes["email"] = email
    if len(changes) == 0:
        return JSONResponse(content={"error": "No changes!"}, status_code=400)

    for key, value in changes.items():
        if key == "email":
            database.update_user(request.state._user["id"], key, value, db)
        elif key == "password":
            new_token = actions.generate_token(request.state._user["id"])

            database.update_user(request.state._user["id"], key, value, db)
            database.change_token(request.state._user["id"], new_token, db)
        # add possible new fields here
    
    return {"username": request.state._user["username"]}

