# compression.py (Updated)
import zlib
import tarfile
import io

def compress(data: bytes) -> bytes:
    """Compresses the given data using zlib."""
    print("[*] Compressing data...")
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    """Decompresses the given zlib-compressed data."""
    print("[*] Decompressing data...")
    return zlib.decompress(data)

def compress_multiple(file_paths: list) -> bytes:
    """
    Bundles multiple files into an in-memory tar archive and then compresses it.
    Returns the compressed byte string of the archive.
    """
    print("[*] Bundling and compressing multiple files...")
    tar_buffer = io.BytesIO()
    
    with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
        for file_path in file_paths:
            try:
                # Add file to the tar archive, using just the filename to avoid full paths
                tar.add(file_path, arcname=os.path.basename(file_path))
                print(f"    - Added {os.path.basename(file_path)}")
            except FileNotFoundError:
                print(f"[!] Warning: File not found and skipped: {file_path}")
    
    tar_buffer.seek(0)
    compressed_data = tar_buffer.getvalue()
    tar_buffer.close()
    return compressed_data

def decompress_multiple(data: bytes, output_dir: str):
    """
    Decompresses data and extracts it as a tar archive into the specified directory.
    """
    print("[*] Decompressing and extracting archive...")
    try:
        tar_buffer = io.BytesIO(data)
        
        with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
            tar.extractall(path=output_dir)
            print(f"[+] Successfully extracted files to: {output_dir}")
        
        tar_buffer.close()
    except Exception as e:
        print(f"[!] An error occurred during decompression/extraction: {e}")

# You'll need to import os for the basename function
import os
