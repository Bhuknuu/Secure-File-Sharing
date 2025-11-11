import streamlit as st
import os
import tempfile
from aes_encryption import encrypt, decrypt
from compression import compress_multiple, decompress_multiple
from signature import sign, verify

# Streamlit Page Config
st.set_page_config(page_title="🔐 Secure File Sharing", layout="wide")

# --- Custom CSS: modern look, no dotted borders ---
st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
        color: white;
    }
    h1, h2, h3, h4, h5, h6, p, span, label {
        color: white !important;
    }
    .block-container {
        padding-top: 2rem;
    }
    .stButton>button {
        width: 100%;
        border-radius: 10px;
        font-weight: 600;
        color: white;
        background-color: #1e3d59;
        border: none;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #2c5364;
        border: none;
    }
    .card:hover {
        transform: scale(1.02);
        box-shadow: 0 6px 25px rgba(255,255,255,0.15);
    }
    .card h3 {
        text-align: center;
        margin-bottom: 1.5rem;
        background: rgba(255,255,255,0.1);
        padding: 0.5rem 1rem;
        border-radius: 10px;
        display: inline-block;
        box-shadow: 0 0 10px rgba(255,255,255,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.markdown("<h1 style='text-align:center;'>Secure File Sharing</h1>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

# --- Initialize Session State ---
if "encrypted_data" not in st.session_state:
    st.session_state["encrypted_data"] = None
if "signature" not in st.session_state:
    st.session_state["signature"] = None
if "decompressed_files" not in st.session_state:
    st.session_state["decompressed_files"] = None

# --- Layout ---
col1, col2 = st.columns([1, 1], gap="large")

# ===================================================
# 📤 SEND SECTION
# ===================================================
with col1:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.markdown("<h3>Send File Securely</h3>", unsafe_allow_html=True)

    uploaded_files = st.file_uploader("Select or drop files to send", accept_multiple_files=True)

    if uploaded_files:
        st.write(f"**Files selected:** {[f.name for f in uploaded_files]}")

    if st.button("Send Securely", use_container_width=True):
        if not uploaded_files:
            st.warning("Please upload at least one file.")
        else:
            try:
                temp_dir = tempfile.mkdtemp()
                file_paths = []
                for file in uploaded_files:
                    temp_path = os.path.join(temp_dir, file.name)
                    with open(temp_path, "wb") as f:
                        f.write(file.getbuffer())
                    file_paths.append(temp_path)

                st.info("Compressing files...")
                compressed_data = compress_multiple(file_paths)

                st.info("Encrypting data...")
                encrypted_data = encrypt(compressed_data)

                st.info("Signing data...")
                signature = sign(encrypted_data)

                st.session_state["encrypted_data"] = encrypted_data
                st.session_state["signature"] = signature

                st.success("✅ Encryption & signing completed successfully!")

            except Exception as e:
                st.error(f"❌ Error: {e}")

    # Download buttons for encrypted and signature files
    if st.session_state["encrypted_data"] and st.session_state["signature"]:
        st.download_button("Download Encrypted File (.enc)",
                           st.session_state["encrypted_data"],
                           "secure_file.enc",
                           "application/octet-stream",
                           use_container_width=True)
        st.download_button("Download Signature (.sig)",
                           st.session_state["signature"].encode(),
                           "secure_file.sig",
                           "text/plain",
                           use_container_width=True)

    st.markdown("</div>", unsafe_allow_html=True)

# ===================================================
# 📥 RECEIVE SECTION
# ===================================================
with col2:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.markdown("<h3>Receive and Decrypt File</h3>", unsafe_allow_html=True)

    enc_file = st.file_uploader("Upload Encrypted File (.enc)", type=["enc"])
    sig_file = st.file_uploader("Upload Signature File (.sig)", type=["sig"])

    if st.button("Decrypt & Verify", use_container_width=True):
        if not enc_file or not sig_file:
            st.warning("Please upload both encrypted and signature files.")
        else:
            try:
                encrypted_data = enc_file.read()
                signature_to_check = sig_file.read().decode("utf-8")

                st.info("Verifying signature...")
                if not verify(encrypted_data, signature_to_check):
                    st.error("❌ Signature verification failed! File may be tampered.")
                else:
                    st.success("✅ Signature verified successfully!")

                    st.info("Decrypting file...")
                    decrypted_data = decrypt(encrypted_data)

                    if decrypted_data is None:
                        st.error("❌ Decryption failed.")
                    else:
                        st.info("Decompressing data...")
                        temp_dir = tempfile.mkdtemp()
                        decompress_multiple(decrypted_data, temp_dir)

                        # Read decompressed files for direct download
                        files_list = []
                        for filename in os.listdir(temp_dir):
                            path = os.path.join(temp_dir, filename)
                            with open(path, "rb") as f:
                                files_list.append((filename, f.read()))

                        st.session_state["decompressed_files"] = files_list
                        st.success(f"Decryption complete! {len(files_list)} files recovered.")

            except Exception as e:
                st.error(f"❌ Error during receiving: {e}")

    # Download individual decompressed files
    if st.session_state["decompressed_files"]:
        st.markdown("<h4>Download Decompressed Files</h4>", unsafe_allow_html=True)
        for filename, data in st.session_state["decompressed_files"]:
            st.download_button(f"📄 Download {filename}",
                               data=data,
                               file_name=filename,
                               mime="application/octet-stream",
                               use_container_width=True)

    st.markdown("</div>", unsafe_allow_html=True)
