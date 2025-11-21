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
from datetime import datetime


st.set_page_config(
    page_title="Secure File Sharing", 
    layout="wide", 
    initial_sidebar_state="expanded",
    menu_items={
        'About': "Secure File Sharing System - Team Cryptics"
    }
)


st.markdown("""
    <style>
    /* Import modern font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* ==================== COLOR SCHEME ==================== */
    /* Dark Mode (Default) */
    :root {
        --bg-primary: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
        --bg-secondary: rgba(30, 61, 89, 0.6);
        --bg-tertiary: rgba(44, 83, 100, 0.4);
        --bg-card: rgba(255, 255, 255, 0.05);
        --bg-card-hover: rgba(255, 255, 255, 0.08);
        --text-primary: #ffffff;
        --text-secondary: rgba(255, 255, 255, 0.7);
        --text-muted: rgba(255, 255, 255, 0.5);
        --border-color: rgba(255, 255, 255, 0.1);
        --border-hover: rgba(255, 255, 255, 0.3);
        --success-color: #10b981;
        --success-bg: rgba(16, 185, 129, 0.1);
        --warning-color: #f59e0b;
        --warning-bg: rgba(245, 158, 11, 0.1);
        --info-color: #3b82f6;
        --info-bg: rgba(59, 130, 246, 0.1);
        --error-color: #ef4444;
        --error-bg: rgba(239, 68, 68, 0.1);
        --shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.4);
    }
    
    /* Light Mode */
    [data-theme="light"], 
    @media (prefers-color-scheme: light) {
        :root {
            --bg-primary: linear-gradient(135deg, #f0f9ff, #e0f2fe, #bae6fd);
            --bg-secondary: rgba(255, 255, 255, 0.8);
            --bg-tertiary: rgba(240, 249, 255, 0.9);
            --bg-card: #ffffff;
            --bg-card-hover: #f8fafc;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --border-color: #e2e8f0;
            --border-hover: #cbd5e1;
            --success-color: #059669;
            --success-bg: #d1fae5;
            --warning-color: #d97706;
            --warning-bg: #fef3c7;
            --info-color: #2563eb;
            --info-bg: #dbeafe;
            --error-color: #dc2626;
            --error-bg: #fee2e2;
            --shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 8px 20px rgba(0, 0, 0, 0.08);
        }
    }
    
    /* ==================== MAIN LAYOUT ==================== */
    .main, [data-testid="stAppViewContainer"] {
        background: var(--bg-primary);
    }
    
    .stApp {
        background: var(--bg-primary);
    }
    
    /* ==================== TYPOGRAPHY ==================== */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary) !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        margin-bottom: 1rem !important;
    }
    
    h1 { font-size: 2.5rem !important; }
    h2 { font-size: 2rem !important; }
    h3 { font-size: 1.5rem !important; }
    
    p, span, label, div[class*="stMarkdown"], .stMarkdown {
        color: var(--text-primary) !important;
    }
    
    .stCaption, small {
        color: var(--text-muted) !important;
    }
    
    /* ==================== INPUTS ==================== */
    .stTextInput label, .stTextArea label, .stSelectbox label, .stFileUploader label {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        margin-bottom: 0.5rem !important;
        font-size: 0.95rem !important;
    }
    
    .stTextInput input, .stTextArea textarea, .stSelectbox select {
        background-color: var(--bg-card) !important;
        color: var(--text-primary) !important;
        border: 2px solid var(--border-color) !important;
        border-radius: 10px !important;
        padding: 0.75rem !important;
        transition: all 0.3s ease !important;
        font-size: 1rem !important;
    }
    
    .stTextInput input:focus, .stTextArea textarea:focus, .stSelectbox select:focus {
        border-color: var(--info-color) !important;
        box-shadow: 0 0 0 3px var(--info-bg) !important;
        outline: none !important;
    }
    
    .stTextInput input::placeholder {
        color: var(--text-muted) !important;
    }
    
    /* ==================== BUTTONS ==================== */
    .stButton>button {
        width: 100%;
        border-radius: 10px;
        font-weight: 600;
        color: white !important;
        background: linear-gradient(135deg, #2563eb, #3b82f6);
        border: none;
        padding: 0.75rem 1.5rem;
        transition: all 0.3s ease;
        box-shadow: var(--shadow);
        font-size: 1rem;
    }
    
    .stButton>button:hover {
        background: linear-gradient(135deg, #1d4ed8, #2563eb);
        transform: translateY(-2px);
        box-shadow: var(--shadow-lg);
    }
    
    .stButton>button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
        background: #94a3b8;
    }
    
    .stDownloadButton>button {
        background: linear-gradient(135deg, var(--success-color), #34d399) !important;
        color: white !important;
    }
    
    .stDownloadButton>button:hover {
        background: linear-gradient(135deg, #059669, var(--success-color)) !important;
    }
    
    /* ==================== STATUS BOXES ==================== */
    .success-box {
        background: var(--success-bg);
        border-left: 4px solid var(--success-color);
        padding: 1.25rem;
        border-radius: 12px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
        box-shadow: var(--shadow);
    }
    
    .warning-box {
        background: var(--warning-bg);
        border-left: 4px solid var(--warning-color);
        padding: 1.25rem;
        border-radius: 12px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
        box-shadow: var(--shadow);
    }
    
    .info-box {
        background: var(--info-bg);
        border-left: 4px solid var(--info-color);
        padding: 1.25rem;
        border-radius: 12px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
        box-shadow: var(--shadow);
    }
    
    .error-box {
        background: var(--error-bg);
        border-left: 4px solid var(--error-color);
        padding: 1.25rem;
        border-radius: 12px;
        margin: 1rem 0;
        color: var(--text-primary) !important;
        box-shadow: var(--shadow);
    }
    
    /* ==================== NOTIFICATION BADGE ==================== */
    .notification-badge {
        position: relative;
        display: inline-block;
    }
    
    .notification-count {
        position: absolute;
        top: -8px;
        right: -8px;
        background: var(--error-color);
        color: white;
        border-radius: 50%;
        width: 20px;
        height: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.75rem;
        font-weight: 700;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
    }
    
    .notification-item {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 0.75rem;
        transition: all 0.3s ease;
        cursor: pointer;
    }
    
    .notification-item:hover {
        background: var(--bg-card-hover);
        border-color: var(--border-hover);
        box-shadow: var(--shadow);
    }
    
    .notification-unread {
        border-left: 4px solid var(--info-color);
        background: var(--info-bg);
    }
    
    /* ==================== COMPRESSION INDICATOR ==================== */
    .compression-info {
        background: var(--bg-card);
        border: 2px dashed var(--border-color);
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    
    .compression-icon {
        font-size: 2rem;
        color: var(--info-color);
    }
    
    .compression-details {
        flex: 1;
    }
    
    .compression-ratio {
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--success-color);
    }
    
    /* ==================== CARDS & CONTAINERS ==================== */
    .stExpander {
        background: var(--bg-card) !important;
        border-radius: 12px !important;
        border: 1px solid var(--border-color) !important;
        margin-bottom: 0.75rem !important;
        box-shadow: var(--shadow) !important;
        transition: all 0.3s ease !important;
    }
    
    .stExpander:hover {
        box-shadow: var(--shadow-lg) !important;
        border-color: var(--border-hover) !important;
    }
    
    .stExpander p, .stExpander span, .stExpander label {
        color: var(--text-primary) !important;
    }
    
    /* ==================== CODE BLOCKS ==================== */
    code {
        background: rgba(0, 0, 0, 0.3) !important;
        color: #10b981 !important;
        padding: 0.3rem 0.6rem !important;
        border-radius: 6px !important;
        font-family: 'Courier New', monospace !important;
        font-size: 0.9rem !important;
    }
    
    pre {
        background: rgba(0, 0, 0, 0.3) !important;
        border-radius: 10px !important;
        padding: 1rem !important;
        border: 1px solid var(--border-color) !important;
    }
    
    /* ==================== FILE UPLOADER ==================== */
    .stFileUploader {
        background: var(--bg-card);
        border-radius: 12px;
        padding: 1.5rem;
        border: 2px dashed var(--border-color);
        transition: all 0.3s ease;
    }
    
    .stFileUploader:hover {
        border-color: var(--info-color);
        background: var(--bg-card-hover);
    }
    
    .stFileUploader label {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
    }
    
    /* ==================== TABS ==================== */
    .stTabs [data-baseweb="tab-list"] {
        gap: 1rem;
        background: transparent;
        padding: 0.5rem 0;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: var(--text-secondary) !important;
        font-weight: 600;
        padding: 0.75rem 1.5rem;
        background: var(--bg-card);
        border-radius: 10px 10px 0 0;
        border: 1px solid var(--border-color);
        transition: all 0.3s ease;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: var(--bg-card-hover);
        color: var(--text-primary) !important;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--info-color) !important;
        background: var(--bg-card);
        border-bottom: 3px solid var(--info-color);
        font-weight: 700;
    }
    
    /* ==================== SIDEBAR ==================== */
    [data-testid="stSidebar"] {
        background: var(--bg-secondary) !important;
        backdrop-filter: blur(10px);
        border-right: 1px solid var(--border-color);
    }
    
    [data-testid="stSidebar"] * {
        color: var(--text-primary) !important;
    }
    
    /* ==================== PROGRESS BAR ==================== */
    .stProgress > div > div {
        background: linear-gradient(90deg, var(--success-color), #34d399) !important;
        border-radius: 10px !important;
    }
    
    /* ==================== ALERTS ==================== */
    .stAlert {
        border-radius: 12px !important;
        padding: 1rem !important;
        margin: 1rem 0 !important;
        border: 1px solid var(--border-color) !important;
    }
    
    /* ==================== RADIO BUTTONS ==================== */
    .stRadio > label {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
    }
    
    .stRadio [role="radiogroup"] {
        gap: 1rem !important;
    }
    
    /* ==================== HORIZONTAL RULE ==================== */
    hr {
        border: none;
        border-top: 2px solid var(--border-color);
        margin: 2rem 0;
        opacity: 0.5;
    }
    
    /* ==================== SCROLLBAR ==================== */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--bg-card);
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--border-color);
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--border-hover);
    }
    
    /* ==================== ANIMATIONS ==================== */
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .stMarkdown, .stButton, .stTextInput {
        animation: slideIn 0.3s ease-out;
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
if 'file_notifications' not in st.session_state:
    st.session_state.file_notifications = []
if 'last_file_check' not in st.session_state:
    st.session_state.last_file_check = None
if 'notification_count' not in st.session_state:
    st.session_state.notification_count = 0

# Helper functions
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def derive_deterministic_key(username, password):
    """Derive deterministic encryption key from username and password"""
    seed = f"{username}:{password}".encode()
    return hashlib.sha256(seed).digest()

def check_for_new_files():
    """Check for new files and create notifications"""
    if not st.session_state.username:
        return
    
    try:
        response = requests.get(f"{API_URL}/files/{st.session_state.username}", timeout=5)
        if response.status_code == 200:
            files = response.json()['files']
            
            # Check for new files since last check
            if st.session_state.last_file_check is not None:
                new_files = [f for f in files if f['uploaded_at'] > st.session_state.last_file_check]
                
                for file_info in new_files:
                    notification = {
                        'id': file_info['file_id'],
                        'sender': file_info['sender'],
                        'filename': file_info['filename'],
                        'time': file_info['uploaded_at'],
                        'read': False
                    }
                    
                    # Add only if not already in notifications
                    # if not any(n['id'] == notification['id'] for n in st.session_state.file_notifications):
                    #     st.session_state.file_notifications.append(notification)
                    #     st.session_state.notification_count += 1
            
            # Update last check time
            if files:
                st.session_state.last_file_check = max(f['uploaded_at'] for f in files)
            elif st.session_state.last_file_check is None:
                st.session_state.last_file_check = datetime.now().isoformat()
    
    except:
        pass

# def mark_notification_read(notification_id):
#     """Mark a notification as read"""
#     for notif in st.session_state.file_notifications:
#         if notif['id'] == notification_id and not notif['read']:
#             notif['read'] = True
#             st.session_state.notification_count = max(0, st.session_state.notification_count - 1)

def register_user(username, password):
    """Register a new user"""
    password_hash = hash_password(password)
    
    try:
        check_response = requests.get(f"{API_URL}/users/{username}/public_key", timeout=2)
        if check_response.status_code == 200:
            return False, "User already exists"
        
        seed = derive_deterministic_key(username, password)
        key_exchange = KeyExchange()
        key_exchange.my_private_key = x25519.X25519PrivateKey.from_private_bytes(seed)
        key_exchange.my_public_key = key_exchange.my_private_key.public_key()
        
        public_key_bytes = key_exchange.my_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
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

# def (message, type="info"):
#     """Add notification to queue"""
#     st.session_state.notifications.append({'message': message, 'type': type})

# def #show_notifications():
#     """Display pending notifications"""
#     if st.session_state.notifications:
#         notification = st.session_state.notifications.pop(0)
#         if notification['type'] == 'success':
#             st.success(notification['message'])
#         elif notification['type'] == 'error':
#             st.error(notification['message'])
#         elif notification['type'] == 'warning':
#             st.warning(notification['message'])
#         else:
#             st.info(notification['message'])

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

def format_file_size(bytes_size):
    """Format bytes to human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} TB"

def calculate_compression_ratio(original_size, compressed_size):
    """Calculate compression ratio"""
    if original_size == 0:
        return 0
    ratio = ((original_size - compressed_size) / original_size) * 100
    return max(0, ratio)

# Check for new files 
if st.session_state.username:
    check_for_new_files()

# Main UI
st.markdown("<h1 style='text-align:center;'>🔒 Secure File Sharing System</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; opacity: 0.8;'>End-to-End Encrypted • ECDH Key Exchange • AES-256-GCM</p>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

#show_notifications()

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
                            
                            seed = derive_deterministic_key(username, password)
                            st.session_state.key_exchange = KeyExchange()
                            st.session_state.key_exchange.my_private_key = x25519.X25519PrivateKey.from_private_bytes(seed)
                            st.session_state.key_exchange.my_public_key = st.session_state.key_exchange.my_private_key.public_key()
                            
                            #(f"Welcome back, {username}! 🎉", "success")
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Please enter both username and password")
            
            with col_btn2:
                if st.button("➡️ Go to Sign Up", use_container_width=True):
                    st.rerun()
        
        else:
            st.markdown("### Create New Account")
            st.markdown("<div class='info-box'>", unsafe_allow_html=True)
            st.markdown("**Join us!** Create your account to start sharing files securely.")
            st.markdown("</div>", unsafe_allow_html=True)
            
            username = st.text_input("Choose Username:", placeholder="Enter a unique username", key="signup_username")
            
            if username:
                valid, msg = validate_username(username)
                if not valid:
                    st.caption(f"⚠️ {msg}")
            
            password = st.text_input("Choose Password:", type="password", placeholder="At least 6 characters", key="signup_password")
            password_confirm = st.text_input("Confirm Password:", type="password", placeholder="Re-enter password", key="signup_password_confirm")
            
            if password:
                valid, msg = validate_password(password)
                if not valid:
                    st.caption(f"⚠️ {msg}")
            
            if password and password_confirm and password != password_confirm:
                st.caption("⚠️ Passwords do not match")
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("Create Account", use_container_width=True):
                    if username and password and password_confirm:
                        username = username.strip()
                        
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
                                    
                                    st.session_state.username = username
                                    st.session_state.password_hash = hash_password(password)
                                    
                                    seed = derive_deterministic_key(username, password)
                                    st.session_state.key_exchange = KeyExchange()
                                    st.session_state.key_exchange.my_private_key = x25519.X25519PrivateKey.from_private_bytes(seed)
                                    st.session_state.key_exchange.my_public_key = st.session_state.key_exchange.my_private_key.public_key()
                                    
                                    #(f"Welcome, {username}! Your account is ready! 🎉", "success")
                                    st.rerun()
                                else:
                                    st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Please fill in all fields")
            
            with col_btn2:
                if st.button("⬅️ Back to Login", use_container_width=True):
                    st.rerun()

# Main Application (after login)
else:
    # Sidebar
    with st.sidebar:
        # Notification Bell
        col_profile,col_info1=st.columns([5,1])
        with col_profile:
            st.markdown("### 👤 User Profile")
        # with col_notif:
        #     if st.session_state.notification_count > 0:
        #         st.markdown(f"""
        #             <div class='notification-badge'>
        #                 🔔
        #                 <span class='notification-count'>{st.session_state.notification_count}</span>
        #             </div>
        #         """, unsafe_allow_html=True)
        #     else:
        #         st.markdown("🔔")
        
        st.markdown(f"**Logged in as:** `{st.session_state.username}`")
        
        # Notifications Panel
        if st.session_state.file_notifications:
            with st.expander(f"📬 Notifications ({len(st.session_state.file_notifications)})", expanded=st.session_state.notification_count > 0):
                for notif in reversed(st.session_state.file_notifications[-5:]):  # Show last 5
                    unread_class = "notification-unread" if not notif['read'] else ""
                    st.markdown(f"""
                        <div class='notification-item {unread_class}'>
                            <strong>{'🆕 ' if not notif['read'] else ''}New File</strong><br>
                            📄 {notif['filename']}<br>
                            👤 From: {notif['sender']}<br>
                            🕐 {notif['time'][:19]}
                        </div>
                    """, unsafe_allow_html=True)
                
                if st.button("✓ Mark All Read", use_container_width=True):
                    for notif in st.session_state.file_notifications:
                        notif['read'] = True
                    st.session_state.notification_count = 0
                    st.rerun()
        
        # st.markdown("---")
        # st.markdown("### 🔑 Key Management")
        # my_public_key = st.session_state.key_exchange.my_public_key.public_bytes(
        #     encoding=serialization.Encoding.Raw,
        #     format=serialization.PublicFormat.Raw
        # )
        # with st.expander("🔓 My Public Key", expanded=False):
        #     st.code(my_public_key.hex(), language="text")
        #     st.caption("This key is persistent and tied to your account")
        
        st.markdown("---")
        st.markdown("###  Establish Secure Connection")
        
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
                                        
                                        #(f"✅ Secure connection established with {selected_user}!", "success")
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
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Main content area
    if not st.session_state.shared_key:
        st.markdown("<div class='warning-box'>", unsafe_allow_html=True)
        st.markdown("### ⚠️ No Active Connection")
        st.markdown("Please establish a secure connection using the sidebar to start sharing files.")
        st.markdown("**Steps:**")
        st.markdown("1. 🔍 Select a partner from the dropdown menu")
        st.markdown("2. 🔗 Click 'Establish Connection'")
        st.markdown("3. 🔑 Keys are exchanged automatically using ECDH")
        st.markdown("4. 📤 Start sending encrypted files!")
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Show compression info
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### 🗜️ Advanced Compression Technology")
        st.markdown("""
            <div class='compression-info'>
                <div class='compression-icon'>📦</div>
                <div class='compression-details'>
                    <strong>Automatic File Compression</strong><br>
                    All files are automatically compressed using TAR + GZIP before encryption.<br>
                    ✓ Reduces file size by 40-70% on average<br>
                    ✓ Faster uploads and downloads<br>
                    ✓ Lower bandwidth usage
                </div>
            </div>
        """, unsafe_allow_html=True)
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
                total_size = sum(f.size for f in uploaded_files)
                
                st.markdown("<div class='info-box'>", unsafe_allow_html=True)
                st.markdown(f"**📁 {len(uploaded_files)} file(s) selected:**")
                for f in uploaded_files:
                    st.markdown(f"• **{f.name}** ({format_file_size(f.size)})")
                st.markdown(f"**Total size:** {format_file_size(total_size)}")
                st.markdown("</div>", unsafe_allow_html=True)
                
                # Compression preview
                estimated_compressed = total_size * 0.5  # Estimate 50% compression
                estimated_ratio = calculate_compression_ratio(total_size, estimated_compressed)
                
                st.markdown(f"""
                    <div class='compression-info'>
                        <div class='compression-icon'>🗜️</div>
                        <div class='compression-details'>
                            <strong>Compression Estimate</strong><br>
                            Original: {format_file_size(total_size)} → Compressed: ~{format_file_size(estimated_compressed)}<br>
                            <span class='compression-ratio'>~{estimated_ratio:.0f}%</span> size reduction expected
                        </div>
                    </div>
                """, unsafe_allow_html=True)
            
            if st.button("🔐 Encrypt & Send", use_container_width=True, disabled=not uploaded_files):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    status_text.text("📦 Preparing files...")
                    progress_bar.progress(10)
                    
                    temp_dir = tempfile.mkdtemp()
                    file_paths = []
                    original_size = 0
                    
                    for file in uploaded_files:
                        temp_path = os.path.join(temp_dir, file.name)
                        with open(temp_path, "wb") as f:
                            content = file.getbuffer()
                            f.write(content)
                            original_size += len(content)
                        file_paths.append(temp_path)
                    
                    status_text.text("🗜️ Compressing files with TAR + GZIP...")
                    progress_bar.progress(30)
                    compressed_data = compress_multiple(file_paths)
                    compressed_size = len(compressed_data)
                    
                    compression_ratio = calculate_compression_ratio(original_size, compressed_size)
                    
                    status_text.text(f"✓ Compressed: {format_file_size(original_size)} → {format_file_size(compressed_size)} ({compression_ratio:.1f}% reduction)")
                    time.sleep(1)
                    
                    status_text.text("🔒 Encrypting with AES-256-GCM (ECDH shared key)...")
                    progress_bar.progress(50)
                    encrypted_data = encrypt_with_key(compressed_data, st.session_state.shared_key)
                    
                    status_text.text(" Generating HMAC-SHA256 digital signature...")
                    progress_bar.progress(70)
                    signature = sign(encrypted_data)
                    
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
                        st.markdown(f"**🆔 File ID:** `{result['file_id']}`")
                        st.markdown(f"**👤 Recipient:** {st.session_state.partner_username}")
                        st.markdown(f"**📦 Files:** {len(uploaded_files)}")
                        st.markdown(f"**📊 Original Size:** {format_file_size(original_size)}")
                        st.markdown(f"**🗜️ Compressed Size:** {format_file_size(compressed_size)}")
                        st.markdown(f"**💾 Space Saved:** {format_file_size(original_size - compressed_size)} ({compression_ratio:.1f}%)")
                        st.markdown("</div>", unsafe_allow_html=True)
                        
                        #("✅ Files sent successfully!", "success")
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
                    check_for_new_files()
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
                            # Check if this is a new notification
                            is_new = any(n['id'] == file_info['file_id'] and not n['read'] 
                                       for n in st.session_state.file_notifications)
                            
                            new_badge = "🆕 " if is_new else ""
                            
                            with st.expander(f"{new_badge}📦 **{file_info['filename']}** from **{file_info['sender']}**", expanded=False):
                                col_info1, col_info2 = st.columns(2)
                                with col_info1:
                                    st.markdown(f"**📅 Uploaded:** {file_info['uploaded_at'][:19]}")
                                with col_info2:
                                    st.markdown(f"**🆔 File ID:** `{file_info['file_id'][:8]}...`")
                                
                                st.markdown("---")
                                
                                # Compression info reminder
                                st.markdown("""
                                    <div class='compression-info'>
                                        <div class='compression-icon'>🗜️</div>
                                        <div class='compression-details'>
                                            <small><strong>Note:</strong> File is compressed with TAR + GZIP and will be automatically decompressed after decryption</small>
                                        </div>
                                    </div>
                                """, unsafe_allow_html=True)
                                
                                if st.button(f"🔓 Decrypt & Download", key=f"download_{idx}", use_container_width=True):
                                    # Mark notification as read
                                    #mark_notification_read(file_info['file_id'])
                                    
                                    progress_bar = st.progress(0)
                                    status_text = st.empty()
                                    
                                    try:
                                        status_text.text(" Downloading from server...")
                                        progress_bar.progress(20)
                                        
                                        enc_response = requests.get(f"{API_URL}/download/{file_info['file_id']}", timeout=30)
                                        sig_response = requests.get(f"{API_URL}/download/{file_info['file_id']}/signature", timeout=30)
                                        
                                        if enc_response.status_code != 200 or sig_response.status_code != 200:
                                            raise Exception("Failed to download files from server")
                                        
                                        encrypted_data = enc_response.content
                                        signature_to_check = sig_response.text
                                        encrypted_size = len(encrypted_data)
                                        
                                        status_text.text(" Verifying HMAC-SHA256 digital signature...")
                                        progress_bar.progress(40)
                                        
                                        if not verify(encrypted_data, signature_to_check):
                                            st.error("⚠️ SECURITY WARNING: Signature verification failed!")
                                            st.error("The file may have been tampered with. Download aborted.")
                                            ##("❌ Signature verification failed!", "error")
                                            status_text.empty()
                                            progress_bar.empty()
                                            continue
                                        
                                        st.success("✅ Signature verified - File is authentic")
                                        
                                        status_text.text("🔓 Decrypting with AES-256-GCM...")
                                        progress_bar.progress(60)
                                        
                                        sender_key = st.session_state.key_pairs.get(
                                            file_info['sender'], 
                                            st.session_state.shared_key
                                        )
                                        
                                        decrypted_data = decrypt_with_key(encrypted_data, sender_key)
                                        
                                        if decrypted_data:
                                            compressed_size = len(decrypted_data)
                                            
                                            status_text.text("🗜️ Decompressing TAR + GZIP archive...")
                                            progress_bar.progress(80)
                                            
                                            temp_dir = tempfile.mkdtemp()
                                            decompress_multiple(decrypted_data, temp_dir)
                                            
                                            files_list = []
                                            decompressed_size = 0
                                            
                                            for filename in os.listdir(temp_dir):
                                                path = os.path.join(temp_dir, filename)
                                                if os.path.isfile(path):
                                                    with open(path, "rb") as f:
                                                        file_data = f.read()
                                                        files_list.append((filename, file_data))
                                                        decompressed_size += len(file_data)
                                            
                                            compression_ratio = calculate_compression_ratio(decompressed_size, compressed_size)
                                            
                                            progress_bar.progress(100)
                                            time.sleep(0.5)
                                            status_text.empty()
                                            progress_bar.empty()
                                            
                                            st.markdown("<div class='success-box'>", unsafe_allow_html=True)
                                            st.markdown(f"### ✅ Successfully processed {len(files_list)} file(s)!")
                                            st.markdown(f"**🗜️ Compression Stats:**")
                                            st.markdown(f"- Original Size: {format_file_size(decompressed_size)}")
                                            st.markdown(f"- Compressed Size: {format_file_size(compressed_size)}")
                                            st.markdown(f"- Space Saved: {format_file_size(decompressed_size - compressed_size)} ({compression_ratio:.1f}%)")
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
                                            
                                            ##(f"✅ Successfully decrypted {len(files_list)} file(s)!", "success")
                                            
                                            try:
                                                import shutil
                                                shutil.rmtree(temp_dir)
                                            except:
                                                pass
                                        else:
                                            st.error("❌ Decryption failed - Invalid key or corrupted data")
                                            ##("❌ Decryption failed!", "error")
                                            status_text.empty()
                                            progress_bar.empty()
                                    
                                    except Exception as e:
                                        status_text.empty()
                                        progress_bar.empty()
                                        st.error(f"❌ Error: {str(e)}")
                                        #(f"❌ Error: {str(e)}", "error")
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