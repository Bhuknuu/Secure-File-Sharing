from OpenSSL import crypto
import os

def generate_self_signed_cert():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().C = "IN"
    cert.get_subject().ST = "Uttarakhand"
    cert.get_subject().L = "Dehradun"
    cert.get_subject().O = "Team Cryptics"
    cert.get_subject().OU = "Secure File Sharing"
    cert.get_subject().CN = "localhost"
    
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    with open("cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open("key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    print("[+] Generated cert.pem and key.pem")
    print("[+] Valid for 1 year")

if __name__ == "__main__":
    if os.path.exists("cert.pem") and os.path.exists("key.pem"):
        print("[!] Certificates already exist")
        overwrite = input("Overwrite? (y/n): ")
        if overwrite.lower() != 'y':
            print("[*] Keeping existing certificates")
            exit(0)
    
    generate_self_signed_cert()