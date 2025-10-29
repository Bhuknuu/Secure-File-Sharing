import os
from compression import compress, decompress, compress_multiple, decompress_multiple
from signature import sign, verify
from aes_encryption import encrypt, decrypt
from file_selector import select_file_to_open, select_file_to_save, select_directory

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def wait_to_continue():
    """Pauses the script and waits for the user to press Enter."""
    input("\nPress Enter to return to the menu...")


def run():
    """Displays the menu and handles user input."""
    while True:
        clear_screen()
        print("--- Secure File Toolkit ---")
        print("1. Compress file(s)")
        print("2. Decompress a file")
        print("3. Decompress an archive (.tar.gz)")
        print("4. Encrypt a file (AES)")
        print("5. Decrypt a file (AES)")
        print("6. Add signature (SHA) to a file")
        print("7. Verify a file's signature")
        print("8. Exit")
        
        choice = input("Enter your choice (1-8): ")


        if choice == '1':
            sub_choice = input("Compress (1) a single file or (2) multiple files into an archive? ")
            if sub_choice == '1':
                input_file = select_file_to_open("Select a file to compress")
                if not input_file: continue
                output_file = select_file_to_save(default_filename="compressed.gz", title="Save compressed file as...")
                if not output_file: continue
                process_file(compress, input_file, output_file)
            elif sub_choice == '2':
                input_files = select_file_to_open("Select multiple files to compress", multiple=True)
                if not input_files: continue
                output_file = select_file_to_save(default_filename="archive.tar.gz", title="Save archive as...")
                if not output_file: continue
                try:
                    compressed_data = compress_multiple(input_files)
                    with open(output_file, 'wb') as f:
                        f.write(compressed_data)
                    print(f"[+] Success! Archive saved to {output_file}")
                    wait_to_continue()
                except Exception as e:
                    print(f"[!] An error occurred: {e}")
                    wait_to_continue()

        elif choice == '2':
            input_file = select_file_to_open("Select a compressed file to decompress")
            if not input_file: continue
            output_file = select_file_to_save(title="Save decompressed file as...")
            if not output_file: continue
            process_file(decompress, input_file, output_file)

        elif choice == '3':
            input_file = select_file_to_open("Select a .tar.gz archive to extract")
            if not input_file: continue
            output_dir = select_directory("Select directory to extract files into")
            if not output_dir: continue
            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
                decompress_multiple(data, output_dir)
                wait_to_continue()
            except Exception as e:
                print(f"[!] An error occurred: {e}")
                wait_to_continue()

        elif choice == '4':
            input_file = select_file_to_open("Select a file to encrypt")
            if not input_file: continue
            output_file = select_file_to_save(default_filename="encrypted.enc", title="Save encrypted file as...")
            if not output_file: continue
            process_file(encrypt, input_file, output_file)

        elif choice == '5':
            input_file = select_file_to_open("Select a file to sign")
            if not input_file: continue
            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
                sig = sign(data)
                sig_file = os.path.splitext(input_file)[0] + ".sig"
                with open(sig_file, 'w') as f:
                    f.write(sig)
                print(f"[+] Signature created and saved to {sig_file}")
                wait_to_continue()
            except Exception as e:
                print(f"[!] An error occurred: {e}")
                wait_to_continue()

        elif choice == '7':
            input_file = select_file_to_open("Select the original file to verify")
            if not input_file: continue
            
            
            sig_file = select_file_to_open("Select the corresponding signature file (.sig)")
            if not sig_file:
                print("[!] No signature file selected. Aborting verification.")
                wait_to_continue()
                continue
            
            try:
                with open(sig_file, 'r') as f:
                    signature_to_check = f.read().strip()
            except Exception as e:
                print(f"[!] Could not read signature file: {e}")
                wait_to_continue()
                continue
            
            if not signature_to_check:
                print("[!] The signature file is empty. Aborting.")
                wait_to_continue()
                continue

            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
                if verify(data, signature_to_check):
                    print("[+] Verification successful: The file is authentic and unmodified.")
                else:
                    print("[!] Verification failed: The file has been tampered with or the signature is incorrect.")
                wait_to_continue()
            except Exception as e:
                print(f"[!] An error occurred during verification: {e}")
                wait_to_continue()

        elif choice == '8':
            print("Exiting.")
            break
        
        else:
            print("[!] Invalid choice. Please enter a number between 1 and 8.")
            wait_to_continue()


def process_file(action_func, input_path, output_path):
    """A helper function to read, process, and write a single file."""
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        
        processed_data = action_func(data)
        
        if processed_data is None:
            print(f"[!] Operation on {input_path} failed.")
            wait_to_continue()
            return

        with open(output_path, 'wb') as f:
            f.write(processed_data)
        
        print(f"[+] Success! Output saved to {output_path}")
        wait_to_continue()

    except FileNotFoundError:
        print(f"[!] Error: The file '{input_path}' was not found.")
        wait_to_continue()
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        wait_to_continue()