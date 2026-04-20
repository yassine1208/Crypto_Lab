from flask import Flask, request, jsonify, send_file
import base64
import hashlib
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
def get_valid_key(key_str):
    if not key_str:
        raise ValueError("Encryption/Decryption key is required.")
    key_bytes = key_str.encode('utf-8')
    # Pad to 16 bytes if smaller, truncate if larger
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

@app.route('/', methods=['GET'])
def index():
    return send_file('index.html')

@app.route('/crypt', methods=['POST'])
def crypt():
    try:
        data = request.get_json()
        return jsonify({"encrypted": encrypt_aes(data.get("text", ""), data.get("key", ""))})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/decrypt', methods=['GET'])
def decrypt():
    try:
        cipher_text = request.args.get("cipherText", "")
        key = request.args.get("key", "")
        return jsonify({"decrypted": decrypt_aes(cipher_text, key)})
    except ValueError as e:
        # Happens on padding errors or incorrect key
        return jsonify({"error": str(e) if str(e) else "Decryption failed (Invalid padding or key)"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/hash', methods=['POST'])
def hash_text():
    data = request.get_json()
    return jsonify({"hash": sha256_hash(data.get("text", ""))})

if __name__ == '__main__':
    app.run(port=8080)
