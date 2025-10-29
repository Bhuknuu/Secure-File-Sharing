import zlib

def compress(data: bytes) -> bytes:
    print("[*]Compressing data...")
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    print("[*]Decompressing data...")
    return zlib.decompress(data)


