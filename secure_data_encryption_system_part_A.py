import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64

# Session initialization
if 'auth' not in st.session_state:
    st.session_state.auth = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'secrets' not in st.session_state:
    st.session_state.secrets = {}
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}

# Security utilities
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_data(text, password):
    cipher = Fernet(generate_key(password))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, password):
    try:
        cipher = Fernet(generate_key(password))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Pages
def login_register_page():
    st.title("🔐 Secure Data Encryption System")
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("Login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                if username in st.session_state.users:
                    if st.session_state.users[username]["password"] == hashlib.sha256(password.encode()).hexdigest():
                        st.session_state.auth = True
                        st.session_state.current_user = username
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
                else:
                    st.error("User not found")

    with tab2:
        with st.form("Register"):
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            if st.form_submit_button("Create Account"):
                if new_user in st.session_state.users:
                    st.error("Username already exists")
                else:
                    st.session_state.users[new_user] = {
                        "password": hashlib.sha256(new_pass.encode()).hexdigest()
                    }
                    st.success("Account created successfully!")

def home_page():
    st.title("🏠 Welcome to Your Secure Vault")
    st.write("Use the sidebar Menu for Navigation.")
    st.info("All data is stored only in memory (session) and encrypted using Fernet.")


def store_data_page():
    st.title("🔏 Store Encrypted Data")
    with st.form("store_form"):
        title = st.text_input("Title for Your Secret")
        secret = st.text_area("Enter Secret Data")
        passkey = st.text_input("Create Passkey", type="password")
        
        if st.form_submit_button("Encrypt & Save"):
            if title and secret and passkey:
                encrypted = encrypt_data(secret, passkey)
                hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()
                
                user = st.session_state.current_user
                if user not in st.session_state.secrets:
                    st.session_state.secrets[user] = []
                
                st.session_state.secrets[user].append({
                    "title": title,
                    "encrypted": encrypted,
                    "passkey_hash": hashed_passkey
                })
                
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ All fields are required!")

def retrieve_data_page():
    st.title("🔐 Retrieve Your Data")
    user = st.session_state.current_user
    
    if user not in st.session_state.secrets or len(st.session_state.secrets[user]) == 0:
        st.info("You have no saved data yet.")
        return

    for idx, secret in enumerate(st.session_state.secrets[user]):
        with st.expander(secret["title"]):
            key_id = f"{user}_{idx}"
            passkey = st.text_input(f"Enter Passkey for {secret['title']}", type="password", key=key_id)

            # Initialize attempt count
            if key_id not in st.session_state.failed_attempts:
                st.session_state.failed_attempts[key_id] = 0

            if passkey:
                hashed_input = hashlib.sha256(passkey.encode()).hexdigest()

                if hashed_input == secret["passkey_hash"]:
                    decrypted = decrypt_data(secret["encrypted"], passkey)
                    if decrypted:
                        st.session_state.failed_attempts[key_id] = 0
                        st.text_area("Decrypted Data", value=decrypted, disabled=True)
                    else:
                        st.error("⚠️ Decryption error.")
                else:
                    st.session_state.failed_attempts[key_id] += 1
                    attempts_left = 3 - st.session_state.failed_attempts[key_id]

                    if attempts_left > 0:
                        st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                    else:
                        st.error("🔒 Too many failed attempts. Please reauthorize.")
                        st.session_state.auth = False
                        st.session_state.current_user = None
                        st.rerun()

def change_password_page():
    st.title("🔑 Change Password")
    with st.form("change_pass"):
        new_pass = st.text_input("New Password", type="password")
        current_pass = st.text_input("Current Password", type="password")
        
        if st.form_submit_button("Update Password"):
            current_hash = hashlib.sha256(current_pass.encode()).hexdigest()
            user = st.session_state.current_user
            
            if current_hash == st.session_state.users[user]["password"]:
                st.session_state.users[user]["password"] = hashlib.sha256(new_pass.encode()).hexdigest()
                st.success("✅ Password updated successfully!")
            else:
                st.error("❌ Current password incorrect.")

def delete_profile_page():
    st.title("🗑️ Delete Account")
    with st.form("delete_form"):
        password = st.text_input("Confirm Password", type="password")
        if st.form_submit_button("Delete My Profile"):
            user = st.session_state.current_user
            if hashlib.sha256(password.encode()).hexdigest() == st.session_state.users[user]["password"]:
                del st.session_state.users[user]
                if user in st.session_state.secrets:
                    del st.session_state.secrets[user]
                st.session_state.auth = False
                st.session_state.current_user = None
                st.success("✅ Account deleted successfully.")
                st.rerun()
            else:
                st.error("❌ Incorrect password.")

# App entry point
def main():
    if not st.session_state.auth:
        login_register_page()
        return
    
    with st.sidebar:
        st.title("🔍 Menu")
        menu = st.radio("Choose", ["Home", "Store Data", "Retrieve Data", "Change Password", "Delete Profile", "Logout"])

    if menu == "Home":
        home_page()
    elif menu == "Store Data":
        store_data_page()
    elif menu == "Retrieve Data":
        retrieve_data_page()
    elif menu == "Change Password":
        change_password_page()
    elif menu == "Delete Profile":
        delete_profile_page()
    elif menu == "Logout":
        st.session_state.auth = False
        st.session_state.current_user = None
        st.rerun()

if __name__ == "__main__":
    main()
