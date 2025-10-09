import os
from compression import compress, decompress
from signature import sign, verify
from aes_encryption import encrypt, decrypt

def process_file(action_func, input_path, output_path):
    """A helper function to read, process, and write a file."""
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        
        processed_data = action_func(data)
        
        if processed_data is None:
            print(f"[!] Operation on {input_path} failed.")
            return

        with open(output_path, 'wb') as f:
            f.write(processed_data)
        
        print(f"[+] Success! Output saved to {output_path}")

    except FileNotFoundError:
        print(f"[!] Error: The file '{input_path}' was not found.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

def run():
    """Displays the menu and handles user input."""
    while True:
        print("\n--- Secure File Toolkit ---")
        print("1. Compress a file")
        print("2. Decompress a file")
        print("3. Encrypt a file (AES)")
        print("4. Decrypt a file (AES)")
        print("5. Add signature (SHA) to a file")
        print("6. Verify a file's signature")
        print("7. Exit")
        
        choice = input("Enter your choice (1-7): ")

        if choice == '1':
            input_file = input("Enter path to file to compress: ")
            output_file = input("Enter path for compressed output file (e.g., file.gz): ")
            process_file(compress, input_file, output_file)

        elif choice == '2':
            input_file = input("Enter path to compressed file: ")
            output_file = input("Enter path for decompressed output file: ")
            process_file(decompress, input_file, output_file)

        elif choice == '3':
            input_file = input("Enter path to file to encrypt: ")
            output_file = input("Enter path for encrypted output file (e.g., file.enc): ")
            process_file(encrypt, input_file, output_file)

        elif choice == '4':
            input_file = input("Enter path to encrypted file: ")
            output_file = input("Enter path for decrypted output file: ")
            process_file(decrypt, input_file, output_file)

        elif choice == '5':
            input_file = input("Enter path to file to sign: ")
            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
                sig = sign(data)
                sig_file = input_file + ".sig"
                with open(sig_file, 'w') as f:
                    f.write(sig)
                print(f"[+] Signature created and saved to {sig_file}")
            except FileNotFoundError:
                print(f"[!] Error: The file '{input_file}' was not found.")

        elif choice == '6':
            input_file = input("Enter path to the original file to verify: ")
            signature_to_check = input("Paste the SHA-256 signature to verify against: ")
            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
                if verify(data, signature_to_check):
                    print("[+] Verification successful: The file is authentic and unmodified.")
                else:
                    print("[!] Verification failed: The file has been tampered with or the signature is incorrect.")
            except FileNotFoundError:
                print(f"[!] Error: The file '{input_file}' was not found.")

        elif choice == '7':
            print("Exiting.")
            break
        
        else:
            print("[!] Invalid choice. Please enter a number between 1 and 7.")
