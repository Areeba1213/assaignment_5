import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key)

# File paths
DATA_FILE = "data.json"
KEY_FILE = "secret.key"

# Load or generate Fernet key
def get_cipher():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return Fernet(key)

cipher = get_cipher()

# Load data from file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

# Save data to file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data (with passkey validation)
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    stored = st.session_state.stored_data

    for key, value in stored.items():
        if key == encrypted_text and value["passkey"] == hashed_passkey:
            try:
                return cipher.decrypt(encrypted_text.encode()).decode()
            except InvalidToken:
                return None
    return None

# Initialize session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Streamlit UI
st.title("🔐 Secure Data Storage App")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📂 Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve your encrypted data securely.")

elif choice == "Store Data":
    st.subheader("📥 Store New Data")
    user_text = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and passkey:
            encrypted = encrypt_data(user_text)
            hashed = hash_passkey(passkey)

            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_data(st.session_state.stored_data)
            st.success("✅ Data stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("❗ Please enter both data and passkey.")

elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Your Data")
    encrypted_input = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success(f"🔐 Decrypted Data: {result}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect! Attempts remaining: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to login.")
                    st.experimental_rerun()
        else:
            st.error("❗ Enter encrypted text and passkey.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized. Go to Retrieve Data.")
        else:
            st.error("❌ Incorrect password.")
