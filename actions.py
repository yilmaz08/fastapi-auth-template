# For token and verification key generation
import secrets
import string
# For email validation
import re
# For password hashing
from hashlib import sha256

def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()

def generate_random_text(length: int = 64) -> str:
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(length))

def generate_token(user_id: int) -> str: # can be improved
    string_to_hash = str(user_id) + generate_random_text(16)
    return sha256((string_to_hash).encode()).hexdigest()

def is_email_valid(email: str) -> bool:
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return re.fullmatch(regex, email) is not None

def matching_regex_in_list(regex_list: list, string: str) -> bool:
    for regex in regex_list:
        if re.match(regex, string):
            return True
    return False

def check_password_strength(password: str) -> bool:
    # Check length
    if len(password) < 8:
        return False
    # Check if it contains at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False
    # Check if it contains at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False
    # Check if it contains at least one digit
    if not re.search(r"\d", password):
        return False
    return True