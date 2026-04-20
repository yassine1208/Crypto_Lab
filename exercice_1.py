import base64
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def get_valid_key(key_str):
    if not key_str:
        raise ValueError("Encryption/Decryption key is required.")
    key_bytes = key_str.encode('utf-8')
    return key_bytes.ljust(16, b'\0')[:16]

def encrypt_aes(text, key_str=""):
    key = get_valid_key(key_str)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode()

def decrypt_aes(encrypted_b64, key_str=""):
    key = get_valid_key(key_str)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_b64)), AES.block_size)
    return decrypted_bytes.decode()

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def main():
    while True:
        print("\n1. Saisir un texte puis le chiffrer")
        print("2. Dechiffrer le texte")
        print("3. Calculer le SHA-256")
        print("4. Comparer deux hashes")
        print("5. Quitter")
        
        choix = input("Choix : ")
        
        if choix == '1':
            text = input("Texte : ")
            key = input("Clé (obligatoire) : ")
            try:
                print(encrypt_aes(text, key))
            except Exception as e:
                print(f"Erreur : {e}")
        elif choix == '2':
            text = input("Texte chiffre (Base64) : ")
            key = input("Clé (obligatoire) : ")
            try:
                print(decrypt_aes(text, key))
            except Exception as e:
                print(f"Erreur : {e}")
        elif choix == '3':
            text = input("Texte : ")
            print(sha256_hash(text))
        elif choix == '4':
            h1 = input("Hash 1 : ")
            h2 = input("Hash 2 : ")
            if h1 == h2:
                print("Identiques")
            else:
                print("Differents")
        elif choix == '5':
            sys.exit(0)

if __name__ == "__main__":
    main()
