from cs50 import SQL

def get_db():
    # return SQL("sqlite:///database.db") # For SQLite
    # return SQL("mysql://username:password@host:port/database") # For MySQL

    return SQL("mysql://yilmaz:123456@localhost:3306/fastapi_auth")

# get user
def get_user_by_id(user_id: int, db: SQL):
    user = db.execute("SELECT * FROM users WHERE id = :id", id=user_id)
    return user[0] if len(user) > 0 else None # If user exists return the user, otherwise return None
def get_user_by_username(username: str, db: SQL):
    user = db.execute("SELECT * FROM users WHERE username = :username", username=username)
    return user[0] if len(user) > 0 else None
def get_user_by_email(email: str, db: SQL):
    user = db.execute("SELECT * FROM users WHERE email = :email", email=email)
    return user[0] if len(user) > 0 else None
def get_user_by_token(token: str, db: SQL):
    user = db.execute("SELECT * FROM users WHERE token = :token", token=token)
    return user[0] if len(user) > 0 else None

# create user
def create_user(username: str, email: str, hashed_password: str, db: SQL):
    db.execute("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)", username=username, email=email, password=hashed_password)
    return get_user_by_username(username, db) # Return the created user

# delete user - not recommended
def delete_user(user_id: int, db: SQL):
    db.execute("DELETE FROM users WHERE id = :id", id=user_id)

# user activation (can be used as an alternative to deleting) - recommended
def deactivate_user(user_id: int, db: SQL):
    db.execute("UPDATE users SET is_active = 0 WHERE id = :id", id=user_id)
def activate_user(user_id: int, db: SQL):
    db.execute("UPDATE users SET is_active = 1 WHERE id = :id", id=user_id)

# user update
def update_user(user_id: int, field: str, value, db: SQL):
    db.execute(f"UPDATE users SET {field} = :value WHERE id = :id", value=value, id=user_id)

# token
def change_token(user_id: int, token: str, db: SQL):
    db.execute("UPDATE users SET token = :token WHERE id = :id", token=token, id=user_id)


# verification key
def create_verification_key(user_id: int, verification_key: str, db: SQL):
    db.execute("INSERT INTO verifications (user_id, verification_key) VALUES (:user_id, :key)", user_id=user_id, key=verification_key)
def delete_verification_key(user_id: int, db: SQL):
    db.execute("DELETE FROM verifications WHERE user_id = :user_id", user_id=user_id)
def get_verification_key(user_id: int, db: SQL):
    key = db.execute("SELECT * FROM verifications WHERE user_id = :user_id", user_id=user_id)
    return key[0]["verification_key"] if len(key) > 0 else None