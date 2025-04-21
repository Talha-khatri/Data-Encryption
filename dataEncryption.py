import streamlit as st
import hashlib
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

stored_data = {}
failed_attempts = {"count": 0}
authorized = {"status": True}

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def store_data(username, text, passkey):
    encrypted_text = cipher.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)
    stored_data[username] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}

def retrieve_data(username, passkey):
    if username in stored_data:
        hashed_input = hash_passkey(passkey)
        if stored_data[username]["passkey"] == hashed_input:
            decrypted_text = cipher.decrypt(stored_data[username]["encrypted_text"].encode()).decode()
            failed_attempts["count"] = 0
            return decrypted_text
        else:
            failed_attempts["count"] += 1
    return None

def login(username, password):
    return username == "admin" and password == "admin"

def home_page():
    st.title("Secure Data Storage")
    choice = st.selectbox("Choose an action", ["Insert Data", "Retrieve Data"])
    if choice == "Insert Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()

def insert_data_page():
    st.subheader("Insert New Data")
    username = st.text_input("Enter a username")
    text = st.text_area("Enter text to store")
    passkey = st.text_input("Enter a passkey", type="password")
    if st.button("Store Data"):
        if username and text and passkey:
            store_data(username, text, passkey)
            st.success("Data stored successfully.")

def retrieve_data_page():
    st.subheader("Retrieve Data")
    username = st.text_input("Enter username")
    passkey = st.text_input("Enter your passkey", type="password")
    if failed_attempts["count"] >= 3 or not authorized["status"]:
        st.warning("Too many failed attempts. Please login again.")
        login_page()
    elif st.button("Retrieve"):
        result = retrieve_data(username, passkey)
        if result:
            st.success("Decrypted Text: " + result)
        else:
            st.error(f"Incorrect passkey. Attempts: {failed_attempts['count']}")

def login_page():
    st.subheader("Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login(username, password):
            failed_attempts["count"] = 0
            authorized["status"] = True
            st.success("Reauthorized successfully.")
        else:
            st.error("Invalid login.")

if authorized["status"]:
    home_page()
else:
    login_page()
