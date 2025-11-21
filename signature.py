import hashlib
import hmac
import os

# WARNING: This is a simplified signature system using HMAC
# For production use, implement proper digital signatures with RSA or ECDSA

# Generate a persistent signing key (in production, this should be user-specific)
SIGNING_KEY_FILE = "signing_key.bin"

def get_signing_key():
    """Get or create a persistent signing key"""
    if os.path.exists(SIGNING_KEY_FILE):
        with open(SIGNING_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        # Generate new key
        key = os.urandom(32)  # 256-bit key
        with open(SIGNING_KEY_FILE, 'wb') as f:
            f.write(key)
        print("[*] Generated new signing key")
        return key

def sign(data: bytes) -> str:
    """
    Generate HMAC-SHA256 signature for data
    
    NOTE: This is a simplified implementation using HMAC.
    For true digital signatures with non-repudiation, use RSA or ECDSA.
    """
    print("[*] Generating HMAC-SHA256 signature...")
    
    # Input validation
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    
    if len(data) == 0:
        raise ValueError("Cannot sign empty data")
    
    try:
        signing_key = get_signing_key()
        signature = hmac.new(signing_key, data, hashlib.sha256).hexdigest()
        print(f"[+] Signature generated: {signature[:16]}...")
        return signature
    except Exception as e:
        print(f"[!] Error generating signature: {e}")
        raise

def verify(data: bytes, signature: str) -> bool:
    """
    Verify HMAC-SHA256 signature
    
    Returns True if signature is valid, False otherwise
    Uses constant-time comparison to prevent timing attacks
    """
    print("[*] Verifying signature...")
    
    # Input validation
    if not isinstance(data, bytes):
        print("[!] Invalid data type for verification")
        return False
    
    if not isinstance(signature, str):
        print("[!] Invalid signature type")
        return False
    
    if len(signature) != 64:  # SHA256 hex is 64 characters
        print("[!] Invalid signature length")
        return False
    
    try:
        signing_key = get_signing_key()
        expected_signature = hmac.new(signing_key, data, hashlib.sha256).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        is_valid = hmac.compare_digest(signature, expected_signature)
        
        if is_valid:
            print("[+] Signature is valid ✓")
        else:
            print("[!] Signature is INVALID ✗")
        
        return is_valid
    
    except Exception as e:
        print(f"[!] Error during verification: {e}")
        return False

def hash_file(file_path: str) -> str:
    """
    Calculate SHA-256 hash of a file
    Useful for integrity checking
    """
    print(f"[*] Hashing file: {file_path}")
    
    hasher = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        file_hash = hasher.hexdigest()
        print(f"[+] File hash: {file_hash}")
        return file_hash
    
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        raise
    except Exception as e:
        print(f"[!] Error hashing file: {e}")
        raise