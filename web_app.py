import streamlit as st
import os
import tempfile
import requests
import hashlib
from aes_encryption import encrypt_with_key, decrypt_with_key
from compression import compress_multiple, decompress_multiple
from signature import sign, verify
from ECDH import KeyExchange
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import time

# Page configuration must be first Streamlit command
st.set_page_config(
    page_title="Secure File Sharing", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# Enhanced CSS with light/dark mode support
st.markdown("""
    <style>
    /* Color scheme variables */
    :root {
        --bg-primary: #0f2027;
        --bg-secondary: #203a43;
        --bg-tertiary: #2c5364;
        --text-primary: #ffffff;
        --text-secondary: rgba(255, 255, 255, 0.8);
        --border-color: rgba(255, 255, 255, 0.2);
        --success-color: #00ff00;
        --warning-color: #ffa500;
        --info-color: #0096ff;
        --error-color: #ff4444;
    }
    
    /* Light mode override */
    @media (prefers-color-scheme: light) {
        :root {
            --bg-primary: #f5f7fa;
            --bg-secondary: #e8ecf1;
            --bg-tertiary: #d1d9e6;
            --text-primary: #2c3e50;
            --text-secondary: #5a6c7d;
            --border-color: rgba(0, 0, 0, 0.1);
        }
    }
    
    /* Main background */
    .main, [data-testid="stAppViewContainer"] {
        background: linear-gradient(135deg, var(--bg-primary), var(--bg-secondary), var(--bg-tertiary));
    }
    
    /* Text colors with proper contrast */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        margin-bottom: 1rem !important;
    }
    
    p, span, label, div[class*="stMarkdown"], .stMarkdown {
        color: var(--text-primary) !important;
    }
    
    /* Input fields */
    .stTextInput label, .stTextArea label, .stSelectbox label {
        color: var(--text-primary) !important;
        font-weight: 500 !important;
        margin-bottom: 0.5rem !important;
    }
    
    .stTextInput input, .stTextArea textarea, .stSelectbox select {
        background-color: rgba(255, 255, 255, 0.1) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        padding: 0.75rem !important;
    }
    
    .stTextInput input::placeholder {
        color: var(--text-secondary) !important;
        opacity: 0.7 !important;
    }
    
    /* Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 10px;
        font-weight: 600;
        color: white !important;
        background: linear-gradient(135deg, #1e3d59, #2c5364);
        border: none;
        padding: 0.75rem 1.5rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .stButton>button:hover {
        background: linear-gradient(135deg, #2c5364, #3a6373);
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
    }
    
    .stButton>button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
    }
    
    /* Download button */
    .stDownloadButton>button {
        background: linear-gradient(135deg, #28a745, #34c759) !important;
        color: white !important;
    }
    
    .stDownloadButton>button:hover {
        background: linear-gradient(135deg, #34c759, #40d668) !important;
    }
    
    /* Status boxes */
    .success-box {
        background-color: rgba(0, 255, 0, 0.1);
        border-left: 4px solid var(--success-color);
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
    }
    
    .warning-box {
        background-color: rgba(255, 165, 0, 0.1);
        border-left: 4px solid var(--warning-color);
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
    }
    
    .info-box {
        background-color: rgba(0, 150, 255, 0.1);
        border-left: 4px solid var(--info-color);
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
    }
    
    .error-box {
        background-color: rgba(255, 68, 68, 0.1);
        border-left: 4px solid var(--error-color);
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
    }
    
    /* Expander */
    .stExpander {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        border: 1px solid var(--border-color);
        margin-bottom: 0.5rem;
    }
    
    .stExpander p, .stExpander span, .stExpander label {
        color: var(--text-primary) !important;
    }
    
    /* Code blocks */
    code {
        background-color: rgba(0, 0, 0, 0.3) !important;
        color: #00ff00 !important;
        padding: 0.2rem 0.4rem !important;
        border-radius: 4px !important;
        font-family: 'Courier New', monospace !important;
    }
    
    /* File uploader */
    .stFileUploader {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        padding: 1rem;
        border: 2px dashed var(--border-color);
    }
    
    .stFileUploader label {
        color: var(--text-primary) !important;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
        background-color: transparent;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: var(--text-secondary) !important;
        font-weight: 600;
        padding: 0.75rem 1.5rem;
        background-color: transparent;
        border-radius: 8px 8px 0 0;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--text-primary) !important;
        background-color: rgba(255, 255, 255, 0.1);
        border-bottom: 3px solid var(--info-color);
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: rgba(0, 0, 0, 0.2);
        backdrop-filter: blur(10px);
    }
    
    [data-testid="stSidebar"] * {
        color: var(--text-primary) !important;
    }
    
    /* Progress bar */
    .stProgress > div > div {
        background-color: var(--success-color);
    }
    
    /* Notifications */
    .stAlert {
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
    
    /* Horizontal rule */
    hr {
        border: none;
        border-top: 1px solid var(--border-color);
        margin: 2rem 0;
    }
    
    /* Caption text */
    .stCaption {
        color: var(--text-secondary) !important;
        font-size: 0.875rem !important;
    }
    </style>
""", unsafe_allow_html=True)

API_URL = "http://localhost:5000/api"

# Initialize session state
if 'username' not in st.session_state:
    st.session_state.username = None
if 'password_hash' not in st.session_state:
    st.session_state.password_hash = None
if 'key_exchange' not in st.session_state:
    st.session_state.key_exchange = None
if 'shared_key' not in st.session_state:
    st.session_state.shared_key = None
if 'partner_username' not in st.session_state:
    st.session_state.partner_username = None
if 'key_pairs' not in st.session_state:
    st.session_state.key_pairs = {}
if 'notifications' not in st.session_state:
    st.session_state.notifications = []
if 'show_login' not in st.session_state:
    st.session_state.show_login = True

# Helper functions
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def derive_deterministic_key(username, password):
    """Derive deterministic encryption key from username and password"""
    seed = f"{username}:{password}".encode()
    return hashlib.sha256(seed).digest()

def register_user(username, password):
    """Register a new user"""
    password_hash = hash_password(password)
    
    try:
        # Check if user exists
        check_response = requests.get(f"{API_URL}/users/{username}/public_key", timeout=2)
        if check_response.status_code == 200:
            return False, "User already exists"
        
        # Generate keys
        seed = derive_deterministic_key(username, password)
        key_exchange = KeyExchange()
        key_exchange.my_private_key = x25519.X25519PrivateKey.from_private_bytes(seed)
        key_exchange.my_public_key = key_exchange.my_private_key.public_key()
        
        public_key_bytes = key_exchange.my_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Register with server
        register_response = requests.post(f"{API_URL}/auth/register", json={
            'username': username,
            'password_hash': password_hash,
            'public_key': public_key_bytes.hex()
        }, timeout=5)
        
        if register_response.status_code == 200:
            return True, "Registration successful!"
        else:
            return False, register_response.json().get('error', 'Registration failed')
    
    except requests.exceptions.RequestException:
        return False, "Server connection error"
    except Exception as e:
        return False, f"Error: {str(e)}"

def login_user(username, password):
    """Login existing user"""
    password_hash = hash_password(password)
    
    try:
        response = requests.post(f"{API_URL}/auth/login", json={
            'username': username,
            'password_hash': password_hash
        }, timeout=5)
        
        if response.status_code == 200:
            return True, "Login successful"
        elif response.status_code == 404:
            return False, "User not found"
        elif response.status_code == 401:
            return False, "Invalid password"
        else:
            return False, "Login failed"
    
    except requests.exceptions.RequestException:
        return False, "Server connection error"
    except Exception as e:
        return False, f"Error: {str(e)}"

def get_user_public_key(username):
    """Retrieve user's public key from server"""
    try:
        response = requests.get(f"{API_URL}/users/{username}/public_key", timeout=5)
        if response.status_code == 200:
            return response.json().get('public_key')
    except:
        pass
    return None

def add_notification(message, type="info"):
    """Add notification to queue"""
    st.session_state.notifications.append({'message': message, 'type': type})

def show_notifications():
    """Display pending notifications"""
    if st.session_state.notifications:
        notification = st.session_state.notifications.pop(0)
        if notification['type'] == 'success':
            st.success(notification['message'])
        elif notification['type'] == 'error':
            st.error(notification['message'])
        elif notification['type'] == 'warning':
            st.warning(notification['message'])
        else:
            st.info(notification['message'])

def check_server():
    """Check if server is running"""
    try:
        response = requests.get(f"{API_URL}/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def validate_username(username):
    """Validate username format"""
    if not username or len(username.strip()) < 3:
        return False, "Username must be at least 3 characters"
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, _ and -"
    return True, "Valid"

def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters"
    return True, "Valid"

# Main UI
st.markdown("<h1 style='text-align:center;'>🔒 Secure File Sharing System</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; opacity: 0.8;'>End-to-End Encrypted File Transfer with ECDH Key Exchange</p>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

show_notifications()

# Server check
if not check_server():
    st.markdown("<div class='error-box'>", unsafe_allow_html=True)
    st.markdown("### ⚠️ Server Not Running")
    st.markdown("The Flask server is not responding. Please start it first:")
    st.markdown("</div>", unsafe_allow_html=True)
    st.code("python server.py", language="bash")
    st.stop()

# Login/Registration Screen
if not st.session_state.username:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        # Toggle between login and signup
        auth_mode = st.radio(
            "Choose Action:",
            ["Login", "Sign Up"],
            horizontal=True,
            key="auth_mode"
        )
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        if auth_mode == "Login":
            st.markdown("### 🔐 Login to Your Account")
            st.markdown("<div class='info-box'>", unsafe_allow_html=True)
            st.markdown("**Welcome back!** Enter your credentials to access secure file sharing.")
            st.markdown("</div>", unsafe_allow_html=True)
            
            username = st.text_input("Username:", placeholder="Enter your username", key="login_username")
            password = st.text_input("Password:", type="password", placeholder="Enter your password", key="login_password")
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("🔓 Login", use_container_width=True):
                    if username and password:
                        username = username.strip()
                        success, message = login_user(username, password)
                        
                        if success:
                            st.session_state.username = username
                            st.session_state.password_hash = hash_password(password)
                            
                            # Initialize key exchange
                            seed = derive_deterministic_key(username, password)
                            st.session_state.key_exchange = KeyExchange()
                            st.session_state.key_exchange.my_private_key = x25519.X25519PrivateKey.from_private_bytes(seed)
                            st.session_state.key_exchange.my_public_key = st.session_state.key_exchange.my_private_key.public_key()
                            
                            add_notification(f"Welcome back, {username}! 🎉", "success")
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Please enter both username and password")
            
            with col_btn2:
                if st.button("➡️ Go to Sign Up", use_container_width=True):
                    st.session_state.show_login = False
                    st.rerun()
        
        else:  # Sign Up
            st.markdown("### ✨ Create New Account")
            st.markdown("<div class='info-box'>", unsafe_allow_html=True)
            st.markdown("**Join us!** Create your account to start sharing files securely.")
            st.markdown("</div>", unsafe_allow_html=True)
            
            username = st.text_input("Choose Username:", placeholder="Enter a unique username", key="signup_username")
            
            # Real-time username validation
            if username:
                valid, msg = validate_username(username)
                if not valid:
                    st.caption(f"⚠️ {msg}")
            
            password = st.text_input("Choose Password:", type="password", placeholder="At least 6 characters", key="signup_password")
            password_confirm = st.text_input("Confirm Password:", type="password", placeholder="Re-enter password", key="signup_password_confirm")
            
            # Real-time password validation
            if password:
                valid, msg = validate_password(password)
                if not valid:
                    st.caption(f"⚠️ {msg}")
            
            if password and password_confirm and password != password_confirm:
                st.caption("⚠️ Passwords do not match")
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("✨ Create Account", use_container_width=True):
                    if username and password and password_confirm:
                        username = username.strip()
                        
                        # Validate inputs
                        valid_username, username_msg = validate_username(username)
                        valid_password, password_msg = validate_password(password)
                        
                        if not valid_username:
                            st.error(f"❌ {username_msg}")
                        elif not valid_password:
                            st.error(f"❌ {password_msg}")
                        elif password != password_confirm:
                            st.error("❌ Passwords do not match")
                        else:
                            with st.spinner("Creating account..."):
                                success, message = register_user(username, password)
                                
                                if success:
                                    st.success(f"✅ {message}")
                                    time.sleep(1)
                                    
                                    # Auto-login after registration
                                    st.session_state.username = username
                                    st.session_state.password_hash = hash_password(password)
                                    
                                    seed = derive_deterministic_key(username, password)
                                    st.session_state.key_exchange = KeyExchange()
                                    st.session_state.key_exchange.my_private_key = x25519.X25519PrivateKey.from_private_bytes(seed)
                                    st.session_state.key_exchange.my_public_key = st.session_state.key_exchange.my_private_key.public_key()
                                    
                                    add_notification(f"Welcome, {username}! Your account is ready! 🎉", "success")
                                    st.rerun()
                                else:
                                    st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Please fill in all fields")
            
            with col_btn2:
                if st.button("⬅️ Back to Login", use_container_width=True):
                    st.session_state.show_login = True
                    st.rerun()

# Main Application (after login)
else:
    # Sidebar
    with st.sidebar:
        st.markdown("### 👤 User Profile")
        st.markdown(f"**Logged in as:** `{st.session_state.username}`")
        
        st.markdown("---")
        st.markdown("### 🔑 Key Management")
        
        my_public_key = st.session_state.key_exchange.my_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        with st.expander("🔓 My Public Key", expanded=False):
            st.code(my_public_key.hex(), language="text")
            st.caption("This key is persistent and tied to your account")
        
        st.markdown("---")
        st.markdown("### 🤝 Establish Secure Connection")
        
        try:
            users_response = requests.get(f"{API_URL}/users/list", timeout=5)
            if users_response.status_code == 200:
                available_users = [u for u in users_response.json().get('users', []) if u != st.session_state.username]
                
                if available_users:
                    selected_user = st.selectbox(
                        "Select Partner:",
                        ["-- Choose a user --"] + available_users,
                        key="partner_select"
                    )
                    
                    if selected_user and selected_user != "-- Choose a user --":
                        if st.button("🔗 Establish Connection", use_container_width=True):
                            with st.spinner(f"Connecting with {selected_user}..."):
                                partner_key = get_user_public_key(selected_user)
                                
                                if partner_key:
                                    try:
                                        partner_key_bytes = bytes.fromhex(partner_key)
                                        shared_key = st.session_state.key_exchange.calculate_shared_secret(partner_key_bytes)
                                        st.session_state.shared_key = shared_key
                                        st.session_state.partner_username = selected_user
                                        st.session_state.key_pairs[selected_user] = shared_key
                                        
                                        add_notification(f"✅ Secure connection established with {selected_user}!", "success")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Key exchange failed: {str(e)}")
                                else:
                                    st.error("❌ Could not retrieve partner's public key")
                else:
                    st.info("ℹ️ No other users registered yet. Create another account to test!")
        except Exception as e:
            st.warning(f"⚠️ Could not fetch user list: {str(e)}")
        
        if st.session_state.shared_key and st.session_state.partner_username:
            st.markdown("---")
            st.markdown("### ✅ Active Connection")
            st.success(f"Connected with: **{st.session_state.partner_username}**")
            
            if st.button("🔄 Change Partner", use_container_width=True):
                st.session_state.shared_key = None
                st.session_state.partner_username = None
                st.rerun()
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            # Clear all session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Main content area
    if not st.session_state.shared_key:
        st.markdown("<div class='warning-box'>", unsafe_allow_html=True)
        st.markdown("### ⚠️ No Active Connection")
        st.markdown("Please establish a secure connection using the sidebar to start sharing files.")
        st.markdown("**Steps:**")
        st.markdown("1. Select a partner from the dropdown menu")
        st.markdown("2. Click '🔗 Establish Connection'")
        st.markdown("3. Keys are exchanged automatically using ECDH")
        st.markdown("4. Start sending encrypted files!")
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        tab1, tab2 = st.tabs(["📤 Send Files", "📥 Receive Files"])
        
        # Send Files Tab
        with tab1:
            st.markdown(f"### 📤 Send Files to {st.session_state.partner_username}")
            
            uploaded_files = st.file_uploader(
                "Select files to send (multiple files allowed)",
                accept_multiple_files=True,
                help="Choose one or more files to send securely",
                key="file_uploader"
            )
            
            if uploaded_files:
                st.markdown("<div class='info-box'>", unsafe_allow_html=True)
                st.markdown(f"**📁 {len(uploaded_files)} file(s) selected:**")
                total_size = sum(f.size for f in uploaded_files)
                for f in uploaded_files:
                    st.markdown(f"• **{f.name}** ({f.size:,} bytes)")
                st.markdown(f"**Total size:** {total_size:,} bytes")
                st.markdown("</div>", unsafe_allow_html=True)
            
            if st.button("🔐 Encrypt & Send", use_container_width=True, disabled=not uploaded_files):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    status_text.text("📦 Preparing files...")
                    progress_bar.progress(10)
                    
                    # Save uploaded files temporarily
                    temp_dir = tempfile.mkdtemp()
                    file_paths = []
                    for file in uploaded_files:
                        temp_path = os.path.join(temp_dir, file.name)
                        with open(temp_path, "wb") as f:
                            f.write(file.getbuffer())
                        file_paths.append(temp_path)
                    
                    status_text.text("🗜️ Compressing files...")
                    progress_bar.progress(30)
                    compressed_data = compress_multiple(file_paths)
                    
                    status_text.text("🔒 Encrypting with ECDH shared key...")
                    progress_bar.progress(50)
                    encrypted_data = encrypt_with_key(compressed_data, st.session_state.shared_key)
                    
                    status_text.text("✍️ Generating digital signature...")
                    progress_bar.progress(70)
                    signature = sign(encrypted_data)
                    
                    # Create temporary files for upload
                    enc_file = tempfile.NamedTemporaryFile(delete=False, suffix='.enc')
                    sig_file = tempfile.NamedTemporaryFile(delete=False, suffix='.sig')
                    enc_file.write(encrypted_data)
                    sig_file.write(signature.encode())
                    enc_file.close()
                    sig_file.close()
                    
                    status_text.text("📡 Uploading to server...")
                    progress_bar.progress(90)
                    
                    with open(enc_file.name, 'rb') as ef, open(sig_file.name, 'rb') as sf:
                        files = {
                            'file': (f'encrypted_{uploaded_files[0].name}.enc', ef),
                            'signature': ('signature.sig', sf)
                        }
                        data = {
                            'sender': st.session_state.username,
                            'recipient': st.session_state.partner_username
                        }
                        response = requests.post(f"{API_URL}/upload", files=files, data=data, timeout=30)
                    
                    # Cleanup
                    os.unlink(enc_file.name)
                    os.unlink(sig_file.name)
                    for fp in file_paths:
                        try:
                            os.unlink(fp)
                        except:
                            pass
                    
                    progress_bar.progress(100)
                    time.sleep(0.5)
                    status_text.empty()
                    progress_bar.empty()
                    
                    if response.status_code == 200:
                        result = response.json()
                        st.markdown("<div class='success-box'>", unsafe_allow_html=True)
                        st.markdown("### ✅ Files Sent Successfully!")
                        st.markdown(f"**File ID:** `{result['file_id']}`")
                        st.markdown(f"**Recipient:** {st.session_state.partner_username}")
                        st.markdown(f"**Files:** {len(uploaded_files)}")
                        st.markdown("</div>", unsafe_allow_html=True)
                        
                        add_notification("✅ Files sent successfully!", "success")
                    else:
                        st.error(f"❌ Upload failed: {response.text}")
                
                except Exception as e:
                    status_text.empty()
                    progress_bar.empty()
                    st.error(f"❌ Error during send: {str(e)}")
        
        # Receive Files Tab
        with tab2:
            st.markdown(f"### 📥 Files Received")
            
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"**Inbox for:** `{st.session_state.username}`")
            with col2:
                if st.button("🔄 Refresh", use_container_width=True, key="refresh_btn"):
                    st.rerun()
            
            try:
                response = requests.get(f"{API_URL}/files/{st.session_state.username}", timeout=5)
                if response.status_code == 200:
                    files = response.json()['files']
                    
                    if files:
                        st.markdown(f"<div class='info-box'>", unsafe_allow_html=True)
                        st.markdown(f"**📬 {len(files)} file(s) available for download**")
                        st.markdown("</div>", unsafe_allow_html=True)
                        
                        for idx, file_info in enumerate(files):
                            with st.expander(f"📦 **{file_info['filename']}** from **{file_info['sender']}**", expanded=False):
                                col_info1, col_info2 = st.columns(2)
                                with col_info1:
                                    st.markdown(f"**📅 Uploaded:** {file_info['uploaded_at']}")
                                with col_info2:
                                    st.markdown(f"**🆔 File ID:** `{file_info['file_id'][:8]}...`")
                                
                                st.markdown("---")
                                
                                if st.button(f"🔓 Decrypt & Download", key=f"download_{idx}", use_container_width=True):
                                    progress_bar = st.progress(0)
                                    status_text = st.empty()
                                    
                                    try:
                                        status_text.text("📡 Downloading from server...")
                                        progress_bar.progress(20)
                                        
                                        enc_response = requests.get(f"{API_URL}/download/{file_info['file_id']}", timeout=30)
                                        sig_response = requests.get(f"{API_URL}/download/{file_info['file_id']}/signature", timeout=30)
                                        
                                        if enc_response.status_code != 200 or sig_response.status_code != 200:
                                            raise Exception("Failed to download files from server")
                                        
                                        encrypted_data = enc_response.content
                                        signature_to_check = sig_response.text
                                        
                                        status_text.text("✍️ Verifying digital signature...")
                                        progress_bar.progress(40)
                                        
                                        if not verify(encrypted_data, signature_to_check):
                                            st.error("⚠️ SECURITY WARNING: Signature verification failed!")
                                            st.error("The file may have been tampered with. Download aborted.")
                                            add_notification("❌ Signature verification failed!", "error")
                                            status_text.empty()
                                            progress_bar.empty()
                                            continue
                                        
                                        st.success("✅ Signature verified - File is authentic")
                                        
                                        status_text.text("🔓 Decrypting with shared key...")
                                        progress_bar.progress(60)
                                        
                                        # Get the correct shared key for this sender
                                        sender_key = st.session_state.key_pairs.get(
                                            file_info['sender'], 
                                            st.session_state.shared_key
                                        )
                                        
                                        decrypted_data = decrypt_with_key(encrypted_data, sender_key)
                                        
                                        if decrypted_data:
                                            status_text.text("📦 Decompressing files...")
                                            progress_bar.progress(80)
                                            
                                            temp_dir = tempfile.mkdtemp()
                                            decompress_multiple(decrypted_data, temp_dir)
                                            
                                            files_list = []
                                            for filename in os.listdir(temp_dir):
                                                path = os.path.join(temp_dir, filename)
                                                if os.path.isfile(path):
                                                    with open(path, "rb") as f:
                                                        files_list.append((filename, f.read()))
                                            
                                            progress_bar.progress(100)
                                            time.sleep(0.5)
                                            status_text.empty()
                                            progress_bar.empty()
                                            
                                            st.markdown("<div class='success-box'>", unsafe_allow_html=True)
                                            st.markdown(f"### ✅ Successfully decrypted {len(files_list)} file(s)!")
                                            st.markdown("</div>", unsafe_allow_html=True)
                                            
                                            st.markdown("**📥 Download Decrypted Files:**")
                                            for file_idx, (filename, data) in enumerate(files_list):
                                                st.download_button(
                                                    f"⬇️ Download {filename}",
                                                    data=data,
                                                    file_name=filename,
                                                    use_container_width=True,
                                                    key=f"dl_{file_info['file_id']}_{file_idx}"
                                                )
                                            
                                            add_notification(f"✅ Successfully decrypted {len(files_list)} file(s)!", "success")
                                            
                                            # Cleanup temp directory
                                            try:
                                                import shutil
                                                shutil.rmtree(temp_dir)
                                            except:
                                                pass
                                        else:
                                            st.error("❌ Decryption failed - Invalid key or corrupted data")
                                            add_notification("❌ Decryption failed!", "error")
                                            status_text.empty()
                                            progress_bar.empty()
                                    
                                    except Exception as e:
                                        status_text.empty()
                                        progress_bar.empty()
                                        st.error(f"❌ Error: {str(e)}")
                                        add_notification(f"❌ Error: {str(e)}", "error")
                    else:
                        st.markdown("<div class='info-box'>", unsafe_allow_html=True)
                        st.markdown("### 📭 No Files Available")
                        st.markdown("Files sent to you will appear here. Ask your partner to send you something!")
                        st.markdown("</div>", unsafe_allow_html=True)
                else:
                    st.error(f"❌ Could not fetch files from server: {response.text}")
            
            except requests.exceptions.RequestException as e:
                st.error(f"❌ Server connection error: {str(e)}")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")