from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class KeyExchange:
    def __init__(self):
        self.my_private_key = None
        self.my_public_key = None
        self.shared_secret = None
    
    def generate_my_keys(self):
        print("[*] Generating my keypair...")
        
        # Generate private key
        self.my_private_key = x25519.X25519PrivateKey.generate()
        
        # Derive public key 
        self.my_public_key = self.my_private_key.public_key()
        
        # Convert to bytes for transmission
        public_key_bytes = self.my_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        print(f"[+] My public key: {public_key_bytes.hex()[:32]}...")
        return public_key_bytes
    
    def calculate_shared_secret(self, their_public_key_bytes):
        print("[*] Calculating shared secret...")
        
        # Convert their public key bytes back to a key object
        their_public_key = x25519.X25519PublicKey.from_public_bytes(
            their_public_key_bytes
        )
        
        # The magic happens here! This creates the shared secret
        raw_shared_secret = self.my_private_key.exchange(their_public_key)
        
        # Use HKDF to derive a proper 32-byte AES key from the shared secret
        # This is like "cleaning up" the raw shared secret
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # We need 32 bytes for AES-256
            salt=None,
            info=b'file-sharing-key',  # Context info
        ).derive(raw_shared_secret)
        
        self.shared_secret = aes_key
        print(f"[+] Shared secret derived: {aes_key.hex()[:32]}...")
        return aes_key
    
    def get_shared_key(self):

        if not self.shared_secret:
            raise ValueError("Shared secret not calculated yet!")
        return self.shared_secret
