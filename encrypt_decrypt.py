# encrypt_decrypt.py
from cryptography.fernet import Fernet
import pandas as pd
import os

# --- Key utilities ---
def generate_key(save_path="key.key"):
    """
    Generates a new Fernet key and saves to save_path.
    Returns the key (bytes).
    """
    key = Fernet.generate_key()
    with open(save_path, "wb") as f:
        f.write(key)
    return key

def load_key(path="key.key"):
    """
    Loads a Fernet key from a file and returns it (bytes).
    Raises FileNotFoundError if path doesn't exist.
    """
    with open(path, "rb") as f:
        key = f.read()
    return key

# --- Single message encrypt/decrypt ---
def encrypt_message(message, key):
    """
    message: str
    key: bytes or path to key file (if str, we will load)
    returns: encrypted message (str, utf-8)
    """
    if isinstance(key, str):
        key = load_key(key)
    f = Fernet(key)
    token = f.encrypt(message.encode("utf-8"))
    return token.decode("utf-8")

def decrypt_message(token, key):
    """
    token: encrypted str
    key: bytes or path to key file
    returns: decrypted str
    """
    if isinstance(key, str):
        key = load_key(key)
    f = Fernet(key)
    plain = f.decrypt(token.encode("utf-8"))
    return plain.decode("utf-8")

# --- CSV batch encrypt/decrypt ---
def encrypt_csv(input_csv, output_csv, column="message", key="key.key"):
    """
    Reads input_csv (expects a column named `column`), encrypts that column, saves to output_csv.
    """
    df = pd.read_csv(input_csv)
    key_bytes = key if isinstance(key, bytes) else load_key(key)
    f = Fernet(key_bytes)
    df[column] = df[column].fillna("").apply(lambda t: f.encrypt(str(t).encode()).decode())
    df.to_csv(output_csv, index=False)
    return output_csv

def decrypt_csv(input_csv, output_csv, column="message", key="key.key"):
    """
    Reads input_csv where `column` is encrypted, decrypts and writes to output_csv.
    """
    df = pd.read_csv(input_csv)
    key_bytes = key if isinstance(key, bytes) else load_key(key)
    f = Fernet(key_bytes)

    def _safe_decrypt(val):
        if pd.isna(val): return ""
        try:
            return f.decrypt(str(val).encode()).decode()
        except Exception:
            # if value is not encrypted or invalid, return as-is
            return val

    df[column] = df[column].apply(_safe_decrypt)
    df.to_csv(output_csv, index=False)
    return output_csv

# --- small CLI test (optional) ---
if __name__ == "__main__":
    # quick manual test if run directly
    if not os.path.exists("key.key"):
        print("Generating key -> key.key")
        generate_key("key.key")
    k = load_key("key.key")
    msg = "Hello world!"
    enc = encrypt_message(msg, k)
    print("Encrypted:", enc)
    dec = decrypt_message(enc, k)
    print("Decrypted:", dec)
