import hashlib

def sign(data: bytes) -> str:
    print("[*] Generating SHA-256 signature...")
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def verify(data: bytes, signature: str) -> bool:
    print("[*] Verifying signature...")
    current_signature = sign(data)
    return current_signature == signature
