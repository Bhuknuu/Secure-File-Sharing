from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets # for random nonce generation

KEY = b'oh-my-super-secret-32-byte-key!!' # temporary and hardcoded 32-byte key. for now :)

def encrypt(data: bytes) -> bytes:
    print("[*] Encrypting data with AES-GCM...")
    aesgcm = AESGCM(KEY)
    
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(encrypted_data: bytes) -> bytes:
    print("[*] Decrypting data with AES-GCM...")
    try:
        aesgcm = AESGCM(KEY) 
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return None
