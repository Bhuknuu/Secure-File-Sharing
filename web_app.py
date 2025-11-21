import streamlit as st
import os
import tempfile
import requests
from aes_encryption import encrypt_with_key, decrypt_with_key
from compression import compress_multiple, decompress_multiple
from signature import sign, verify
from ECDH import KeyExchange
from cryptography.hazmat.primitives import serialization

st.set_page_config(page_title="🔒 Secure File Sharing", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
        color: white;
    }
    h1, h2, h3, h4, h5, h6, p, span, label, div {
        color: white !important;
    }
    .stButton>button {
        width: 100%;
        border-radius: 10px;
        font-weight: 600;
        color: white;
        background-color: #1e3d59;
        border: none;
        padding: 0.75rem;
    }
    .stButton>button:hover {
        background-color: #2c5364;
        transform: translateY(-2px);
    }
    .success-box {
        background-color: rgba(0, 255, 0, 0.1);
        border-left: 4px solid #00ff00;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: rgba(255, 165, 0, 0.1);
        border-left: 4px solid #ffa500;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .info-box {
        background-color: rgba(0, 150, 255, 0.1);
        border-left: 4px solid #0096ff;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .stExpander {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

API_URL = "http://localhost:5000/api"

if 'username' not in st.session_state:
    st.session_state.username = None
if 'key_exchange' not in st.session_state:
    st.session_state.key_exchange = None
if 'shared_key' not in st.session_state:
    st.session_state.shared_key = None
if 'partner_username' not in st.session_state:
    st.session_state.partner_username = None
if 'key_pairs' not in st.session_state:
    st.session_state.key_pairs = {}

def check_server():
    try:
        response = requests.get(f"{API_URL}/health", timeout=2)
        return response.status_code == 200
    except:
        return False

st.markdown("<h1 style='text-align:center;'>🔒 Secure File Sharing System</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; opacity: 0.8;'>End-to-End Encrypted File Transfer with ECDH Key Exchange</p>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

if not check_server():
    st.error("⚠️ Server is not running!")
    st.info("Please start the server first:")
    st.code("python server.py", language="bash")
    st.stop()

if not st.session_state.username:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("### 🔐 Login to Secure File Sharing")
        st.markdown("<div class='info-box'>", unsafe_allow_html=True)
        st.markdown("**Welcome!** Enter your username to start secure file sharing.")
        st.markdown("</div>", unsafe_allow_html=True)
        
        username = st.text_input("Username:", placeholder="Enter your username")
        
        if st.button("🚀 Login", use_container_width=True):
            if username and username.strip():
                st.session_state.username = username.strip()
                st.session_state.key_exchange = KeyExchange()
                st.session_state.key_exchange.generate_my_keys()
                st.success(f"✅ Welcome {username}!")
                st.rerun()
            else:
                st.warning("⚠️ Please enter a valid username")

else:
    with st.sidebar:
        st.markdown("### 👤 User Profile")
        st.markdown(f"**Logged in as:** `{st.session_state.username}`")
        
        st.markdown("---")
        st.markdown("### 🔑 Key Management")
        
        my_public_key = st.session_state.key_exchange.my_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        with st.expander("📤 My Public Key", expanded=False):
            st.code(my_public_key.hex(), language="text")
            st.caption("Share this key with your communication partner")
        
        st.markdown("---")
        st.markdown("### 🔗 Establish Secure Connection")
        
        partner_username = st.text_input("Partner's Username:", placeholder="Enter username")
        partner_key = st.text_area("Partner's Public Key:", placeholder="Paste their public key here", height=100)
        
        if st.button("🤝 Establish Connection", use_container_width=True):
            if partner_username and partner_key:
                try:
                    partner_key_bytes = bytes.fromhex(partner_key.strip())
                    shared_key = st.session_state.key_exchange.calculate_shared_secret(partner_key_bytes)
                    st.session_state.shared_key = shared_key
                    st.session_state.partner_username = partner_username
                    st.session_state.key_pairs[partner_username] = shared_key
                    st.success(f"✅ Secure connection established with {partner_username}!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Key exchange failed: {str(e)}")
            else:
                st.warning("⚠️ Please enter both username and public key")
        
        if st.session_state.shared_key:
            st.markdown("---")
            st.markdown("### ✅ Active Connection")
            st.success(f"🔐 Connected with: **{st.session_state.partner_username}**")
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.username = None
            st.session_state.key_exchange = None
            st.session_state.shared_key = None
            st.session_state.partner_username = None
            st.session_state.key_pairs = {}
            st.rerun()
    
    if not st.session_state.shared_key:
        st.markdown("<div class='warning-box'>", unsafe_allow_html=True)
        st.markdown("### ⚠️ No Active Connection")
        st.markdown("Please establish a secure connection using the sidebar to start sharing files.")
        st.markdown("**Steps:**")
        st.markdown("1. Share your public key with your partner")
        st.markdown("2. Get their public key")
        st.markdown("3. Enter their username and public key in the sidebar")
        st.markdown("4. Click 'Establish Connection'")
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        tab1, tab2 = st.tabs(["📤 Send Files", "📥 Receive Files"])
        
        with tab1:
            st.markdown(f"### 📤 Send Files to {st.session_state.partner_username}")
            
            uploaded_files = st.file_uploader(
                "Select files to send (multiple files allowed)",
                accept_multiple_files=True,
                help="Choose one or more files to send securely"
            )
            
            if uploaded_files:
                st.markdown("<div class='info-box'>", unsafe_allow_html=True)
                st.markdown(f"**{len(uploaded_files)} file(s) selected:**")
                for f in uploaded_files:
                    st.markdown(f"- 📄 {f.name} ({f.size:,} bytes)")
                st.markdown("</div>", unsafe_allow_html=True)
            
            col1, col2 = st.columns([3, 1])
            with col1:
                send_button = st.button("🔒 Encrypt & Send", use_container_width=True, disabled=not uploaded_files)
            
            if send_button and uploaded_files:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    status_text.text("📦 Preparing files...")
                    progress_bar.progress(10)
                    
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
                    
                    status_text.text("🔐 Encrypting with ECDH shared key...")
                    progress_bar.progress(50)
                    encrypted_data = encrypt_with_key(compressed_data, st.session_state.shared_key)
                    
                    status_text.text("✍️ Generating digital signature...")
                    progress_bar.progress(70)
                    signature = sign(encrypted_data)
                    
                    enc_file = tempfile.NamedTemporaryFile(delete=False, suffix='.enc')
                    sig_file = tempfile.NamedTemporaryFile(delete=False, suffix='.sig')
                    enc_file.write(encrypted_data)
                    sig_file.write(signature.encode())
                    enc_file.close()
                    sig_file.close()
                    
                    status_text.text("📤 Uploading to server...")
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
                    
                    progress_bar.progress(100)
                    status_text.empty()
                    
                    if response.status_code == 200:
                        result = response.json()
                        st.markdown("<div class='success-box'>", unsafe_allow_html=True)
                        st.markdown("### ✅ Files Sent Successfully!")
                        st.markdown(f"**File ID:** `{result['file_id']}`")
                        st.markdown(f"**Recipient:** {st.session_state.partner_username}")
                        st.markdown("</div>", unsafe_allow_html=True)
                        st.balloons()
                    else:
                        st.error(f"❌ Upload failed: {response.text}")
                
                except Exception as e:
                    st.error(f"❌ Error during send: {str(e)}")
        
        with tab2:
            st.markdown(f"### 📥 Files Received for {st.session_state.username}")
            
            col1, col2 = st.columns([3, 1])
            with col2:
                if st.button("🔄 Refresh", use_container_width=True):
                    st.rerun()
            
            try:
                response = requests.get(f"{API_URL}/files/{st.session_state.username}", timeout=5)
                if response.status_code == 200:
                    files = response.json()['files']
                    
                    if files:
                        st.markdown(f"<div class='info-box'>", unsafe_allow_html=True)
                        st.markdown(f"**{len(files)} file(s) available for download**")
                        st.markdown("</div>", unsafe_allow_html=True)
                        
                        for idx, file_info in enumerate(files):
                            with st.expander(f"📁 {file_info['filename']} from **{file_info['sender']}**", expanded=True):
                                col1, col2 = st.columns([2, 1])
                                with col1:
                                    st.markdown(f"**Uploaded:** {file_info['uploaded_at']}")
                                    st.markdown(f"**File ID:** `{file_info['file_id']}`")
                                
                                if st.button(f"🔓 Decrypt & Download", key=f"download_{idx}", use_container_width=True):
                                    progress_bar = st.progress(0)
                                    status_text = st.empty()
                                    
                                    try:
                                        status_text.text("📥 Downloading from server...")
                                        progress_bar.progress(20)
                                        
                                        enc_response = requests.get(f"{API_URL}/download/{file_info['file_id']}", timeout=30)
                                        sig_response = requests.get(f"{API_URL}/download/{file_info['file_id']}/signature", timeout=30)
                                        
                                        encrypted_data = enc_response.content
                                        signature_to_check = sig_response.text
                                        
                                        status_text.text("🔍 Verifying digital signature...")
                                        progress_bar.progress(40)
                                        
                                        if not verify(encrypted_data, signature_to_check):
                                            st.error("❌ SECURITY WARNING: Signature verification failed! File may be tampered.")
                                        else:
                                            st.success("✅ Signature verified - File is authentic")
                                            
                                            status_text.text("🔓 Decrypting with shared key...")
                                            progress_bar.progress(60)
                                            
                                            sender_key = st.session_state.key_pairs.get(file_info['sender'], st.session_state.shared_key)
                                            decrypted_data = decrypt_with_key(encrypted_data, sender_key)
                                            
                                            if decrypted_data:
                                                status_text.text("📦 Decompressing files...")
                                                progress_bar.progress(80)
                                                
                                                temp_dir = tempfile.mkdtemp()
                                                decompress_multiple(decrypted_data, temp_dir)
                                                
                                                files_list = []
                                                for filename in os.listdir(temp_dir):
                                                    path = os.path.join(temp_dir, filename)
                                                    with open(path, "rb") as f:
                                                        files_list.append((filename, f.read()))
                                                
                                                progress_bar.progress(100)
                                                status_text.empty()
                                                
                                                st.markdown("<div class='success-box'>", unsafe_allow_html=True)
                                                st.markdown(f"### ✅ Successfully decrypted {len(files_list)} file(s)!")
                                                st.markdown("</div>", unsafe_allow_html=True)
                                                
                                                st.markdown("**📥 Download Decrypted Files:**")
                                                for filename, data in files_list:
                                                    st.download_button(
                                                        f"💾 {filename}",
                                                        data=data,
                                                        file_name=filename,
                                                        use_container_width=True,
                                                        key=f"dl_{file_info['file_id']}_{filename}"
                                                    )
                                                
                                                st.success("🎉 All files ready for download!")
                                            else:
                                                st.error("❌ Decryption failed - Invalid key or corrupted data")
                                    
                                    except Exception as e:
                                        st.error(f"❌ Error: {str(e)}")
                    else:
                        st.info("📭 No files available. Files sent to you will appear here.")
                else:
                    st.error(f"❌ Could not fetch files from server: {response.text}")
            
            except Exception as e:
                st.error(f"❌ Server connection error: {str(e)}")