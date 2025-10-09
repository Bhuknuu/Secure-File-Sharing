from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# IMPORTANT: This is a temporary, hardcoded 32-byte key.
# In a real application, this key will be generated through ECDH.
KEY = b'oh-super-secret-32-byte-long-key!!'

def encrypt(data: bytes) -> bytes:
    """
    Encrypts data using AES-GCM with the hardcoded key.
    Returns a byte string containing the nonce (12 bytes) followed by the ciphertext.
    """
    print("[*] Encrypting data with AES-GCM...")
    aesgcm = AESGCM(KEY)
    # A nonce (Number used once) is required for GCM. 12 bytes is a standard size.
    nonce = AESGCM.generate_nonce(bit_length=96)
    ciphertext = aesgcm.encrypt(nonce, data, None) # 'None' for additional authenticated data
    # We must store the nonce alongside the ciphertext to decrypt it later.
    return nonce + ciphertext

def decrypt(encrypted_data: bytes) -> bytes:
    """
    Decrypts AES-GCM encrypted data.
    Expects the input to be the nonce (12 bytes) followed by the ciphertext.
    Returns the original decrypted data.
    """
    print("[*] Decrypting data with AES-GCM...")
    try:
        aesgcm = AESGCM(KEY)
        # Extract the nonce from the first 12 bytes
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return None
