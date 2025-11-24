from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct

def gf_multiply(x, y):
    result = 0
    
    for i in range(128):
        # If bit i of y is set, XOR result with x
        if y & (1 << (127 - i)):
            result ^= x
        # Check if leftmost bit of x is 1
        if x & 1:
            x = (x >> 1) ^ 0xE1000000000000000000000000000000  # Reduction polynomial
        else:
            x >>= 1
    
    return result

def bytes_to_int(data):
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(num):
    return num.to_bytes(16, byteorder='big')

class GHASH:
    
    def __init__(self, h_key):
        self.h = bytes_to_int(h_key)
    
    def compute(self, ciphertext):
        # Start with zero
        y = 0        
        # Process ciphertext in 16-byte blocks
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            # Pad last block if needed
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            
            # Convert to integer and mix
            block_int = bytes_to_int(block)
            y = gf_multiply(y ^ block_int, self.h)
        
        # Add length block (AAD_len || C_len)
        # We have no AAD, so just ciphertext length in bits
        len_block = struct.pack('>QQ', 0, len(ciphertext) * 8)
        len_int = bytes_to_int(len_block)
        y = gf_multiply(y ^ len_int, self.h)
        
        return int_to_bytes(y)

class CTR_Mode:
    
    def __init__(self, cipher, nonce):

        self.cipher = cipher
        # Counter format: [nonce 12 bytes][counter 4 bytes]
        self.nonce = nonce
        self.counter = 1  # Start from 1 (0 reserved for tag)
    
    def _get_counter_block(self, counter_val):
        """Create counter block: nonce || counter"""
        return self.nonce + struct.pack('>I', counter_val)
    
    def _increment_counter(self):
        """Increment counter (wraps at 2^32)"""
        self.counter = (self.counter + 1) & 0xFFFFFFFF
    
    def encrypt(self, plaintext):
        ciphertext = bytearray()
        
        # Process in 16-byte blocks
        for i in range(0, len(plaintext), 16):
            # Get plaintext block
            pt_block = plaintext[i:i+16]
            
            # Encrypt counter
            counter_block = self._get_counter_block(self.counter)
            encrypted_counter = self.cipher.encrypt(counter_block)
            
            # XOR with plaintext
            ct_block = bytes(a ^ b for a, b in zip(pt_block, encrypted_counter[:len(pt_block)]))
            ciphertext.extend(ct_block)
            
            self._increment_counter()
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)  # Same operation!

class MyAESGCM:
    """
    Custom AES-GCM Implementation
    
    GCM = Galois/Counter Mode
    = CTR mode (confidentiality) + GHASH (authenticity)
    
    Security guarantees:
    - Confidentiality: Data is encrypted (CTR mode)
    - Authenticity: Tag proves data not tampered (GHASH)
    - AEAD: Authenticated Encryption with Associated Data
    """
    
    def __init__(self, key):
        """Initialize with 256-bit key"""
        if len(key) != 32:
            raise ValueError("[!] Key must be 32 bytes (256 bits)")
        self.key = key
    
    def encrypt_data(self, plaintext):
        """
        Encrypt and authenticate plaintext
        
        Steps:
        1. Generate random nonce
        2. Create hash subkey (H = E(K, 0^128))
        3. Encrypt plaintext with CTR mode
        4. Compute authentication tag with GHASH
        5. Encrypt tag
        6. Package: nonce || ciphertext || tag
        """
        print("[*] Encrypting with AES-GCM from scratch...")
        
        # Step 1: Generate random 96-bit nonce
        nonce = get_random_bytes(12)
        
        # Step 2: Create base AES cipher
        base_cipher = AES.new(self.key, AES.MODE_ECB)
        
        # Step 3: Generate hash subkey H = E(K, 0^128)
        # This is used for authentication
        zero_block = b'\x00' * 16
        h_key = base_cipher.encrypt(zero_block)
        
        # Step 4: Encrypt plaintext using CTR mode
        ctr = CTR_Mode(base_cipher, nonce)
        ciphertext = ctr.encrypt(plaintext)
        
        # Step 5: Compute authentication tag
        ghash = GHASH(h_key)
        auth_tag_raw = ghash.compute(ciphertext)
        
        # Step 6: Encrypt the tag using counter 0
        counter_0 = nonce + b'\x00\x00\x00\x01'
        encrypted_counter_0 = base_cipher.encrypt(counter_0)
        
        # Final tag = GHASH output XOR encrypted counter 0
        auth_tag = bytes(a ^ b for a, b in zip(auth_tag_raw, encrypted_counter_0))
        
        # Package everything: nonce || ciphertext || tag
        encrypted_package = nonce + ciphertext + auth_tag
        
        print(f"[+] Encrypted {len(plaintext)} bytes")
        print(f"    Nonce: {len(nonce)} bytes")
        print(f"    Ciphertext: {len(ciphertext)} bytes")
        print(f"    Tag: {len(auth_tag)} bytes")
        
        return encrypted_package
    
    def decrypt_data(self, encrypted_package):
        """
        Decrypt and verify ciphertext
        
        Steps:
        1. Extract nonce, ciphertext, tag
        2. Recompute authentication tag
        3. Verify tag matches (constant-time comparison)
        4. If valid, decrypt ciphertext
        5. Return plaintext or None if tampered
        """
        print("[*] Decrypting with AES-GCM from scratch...")
        
        try:
            # Step 1: Extract components
            if len(encrypted_package) < 28:  # 12 (nonce) + 16 (tag)
                raise ValueError("Encrypted data too short")
            
            nonce = encrypted_package[:12]
            tag = encrypted_package[-16:]
            ciphertext = encrypted_package[12:-16]
            
            # Step 2: Create base AES cipher
            base_cipher = AES.new(self.key, AES.MODE_ECB)
            
            # Step 3: Generate hash subkey
            zero_block = b'\x00' * 16
            h_key = base_cipher.encrypt(zero_block)
            
            # Step 4: Recompute authentication tag
            ghash = GHASH(h_key)
            auth_tag_raw = ghash.compute(ciphertext)
            
            # Encrypt counter 0 for tag
            counter_0 = nonce + b'\x00\x00\x00\x01'
            encrypted_counter_0 = base_cipher.encrypt(counter_0)
            
            # Expected tag
            expected_tag = bytes(a ^ b for a, b in zip(auth_tag_raw, encrypted_counter_0))
            
            # Step 5: Verify tag (constant-time comparison)
            if not self._constant_time_compare(tag, expected_tag):
                print("[!] SECURITY WARNING: Authentication tag mismatch!")
                print("[!] Data has been tampered with or corrupted!")
                return None
            
            print("[+] Authentication tag verified ✓")
            
            # Step 6: Decrypt ciphertext
            ctr = CTR_Mode(base_cipher, nonce)
            plaintext = ctr.decrypt(ciphertext)
            
            print(f"[+] Decrypted {len(plaintext)} bytes successfully")
            
            return plaintext
        
        except Exception as e:
            print(f"[!] SECURITY WARNING: {e}")
            return None
    
    def _constant_time_compare(self, a, b):
        """
        Compare two byte strings in constant time
        Prevents timing attacks!
        
        Why? If we return early on mismatch, attacker can
        measure time to guess correct bytes one by one.
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0

def encrypt_with_key(data, key):
    cipher = MyAESGCM(key)
    return cipher.encrypt_data(data)

def decrypt_with_key(encrypted_data, key):
    cipher = MyAESGCM(key)
    return cipher.decrypt_data(encrypted_data)