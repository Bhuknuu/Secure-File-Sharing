# compression.py
import zlib

def compress(data: bytes) -> bytes:
    """
    Compresses the given data using zlib.
    Returns the compressed byte string.
    """
    print("[*] Compressing data...")
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    """
    Decompresses the given zlib-compressed data.
    Returns the original byte string.
    """
    print("[*] Decompressing data...")
    return zlib.decompress(data)


