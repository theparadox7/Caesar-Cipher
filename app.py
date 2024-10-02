from flask import Flask, render_template, request
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# Home Page with Caesar Cipher Decryption Logic
@app.route('/', methods=['GET', 'POST'])
def index():
    decrypted_message = None
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        shift = int(request.form['shift'])

        # Caesar Cipher Logic for Decryption
        def caesar_shift(text, shift):
            result = []
            for char in text:
                if char.isalpha():
                    shift_base = 65 if char.isupper() else 97
                    result.append(chr((ord(char) - shift_base - shift) % 26 + shift_base))
                else:
                    result.append(char)
            return ''.join(result)

        decrypted_message = caesar_shift(ciphertext, shift)

    return render_template('index.html', decrypted_message=decrypted_message)

# MD5 Hashing
@app.route('/md5', methods=['GET', 'POST'])
def md5():
    hashed_message = None
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        hashed_message = hashlib.md5(plaintext.encode()).hexdigest()
    return render_template('md5.html', hashed_message=hashed_message)

# SHA-256 Hashing
@app.route('/sha', methods=['GET', 'POST'])
def sha():
    hashed_message = None
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        hashed_message = hashlib.sha256(plaintext.encode()).hexdigest()
    return render_template('sha.html', hashed_message=hashed_message)

# RSA Encryption/Decryption
@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    result_message = None
    if request.method == 'POST':
        action = request.form['action']
        key_pem = request.form['key']
        message = request.form['message']

        try:
            key = serialization.load_pem_private_key(
                key_pem.encode(),
                password=None,
            )
        except Exception as e:
            return render_template('rsa.html', result_message=f"Invalid Key: {e}")

        if action == 'Encrypt':
            try:
                ciphertext = key.public_key().encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                result_message = ciphertext.hex()
            except Exception as e:
                result_message = f"Encryption failed: {e}"

        elif action == 'Decrypt':
            try:
                decrypted_message = key.decrypt(
                    bytes.fromhex(message),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                result_message = decrypted_message.decode()
            except Exception as e:
                result_message = f"Decryption failed: {e}"

    return render_template('rsa.html', result_message=result_message)

# Substitution Cipher
@app.route('/substitution_cipher', methods=['GET', 'POST'])
def substitution_cipher():
    decrypted_message = None
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        key = request.form['key'].upper()

        if len(key) != 26:
            return render_template('substitution_cipher.html', decrypted_message="Key must be 26 characters long.")

        def decrypt(ciphertext, key):
            alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            key_map = str.maketrans(key, alphabet)
            return ciphertext.upper().translate(key_map)

        decrypted_message = decrypt(ciphertext, key)

    return render_template('substitution_cipher.html', decrypted_message=decrypted_message)

if __name__ == '__main__':
    app.run(debug=True)
