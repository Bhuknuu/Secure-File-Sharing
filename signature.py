import hashlib

def sign(data: bytes) -> str:
    """
    Creates a SHA-256 hash (signature) of the data.
    Returns the signature as a hex string.
    """
    print("[*] Generating SHA-256 signature...")
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def verify(data: bytes, signature: str) -> bool:
    """
    Verifies if the data matches the given SHA-256 signature.
    Returns True if they match, False otherwise.
    """
    print("[*] Verifying signature...")
    current_signature = sign(data)
    return current_signature == signature
