# from flask import Flask, render_template, request

# app = Flask(__name__)

# def caesar_decrypt(ciphertext, shift):
#     plaintext = ""
#     for char in ciphertext:
#         if char.isalpha():
#             offset = 65 if char.isupper() else 97
#             decrypted_char = chr((ord(char) - offset - shift) % 26 + offset)
#             plaintext += decrypted_char
#         else:
#             plaintext += char
#     return plaintext


# @app.route("/", methods=["GET", "POST"])
# def index():
#     decrypted_message = ""
#     ciphertext = ""
#     shift = ""
#     if request.method == "POST":
#         ciphertext = request.form.get("ciphertext")
#         shift = request.form.get("shift")
#         if ciphertext and shift.isdigit():
#             shift = int(shift)
#             decrypted_message = caesar_decrypt(ciphertext, shift)
#     return render_template("index.html", ciphertext=ciphertext, shift=shift, decrypted_message=decrypted_message)

# @app.route("/substitution_cipher")
# def substitution_cipher():
#     return render_template("substitution_cipher.html")

# @app.route("/rsa")
# def rsa():
#     return render_template("rsa.html")

# @app.route("/md5")
# def md5():
#     return render_template("md5.html")

# @app.route("/sha")
# def sha():
#     return render_template("sha.html")

# if __name__ == "__main__":
#     app.run(debug=True)
 

from flask import Flask, render_template, request
import hashlib
from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/md5', methods=['GET', 'POST'])
def md5():
    hashed_message = None
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        hashed_message = hashlib.md5(plaintext.encode()).hexdigest()
    return render_template('md5.html', hashed_message=hashed_message)

@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    result_message = None
    if request.method == 'POST':
        action = request.form['action']
        key_pem = request.form['key']
        plaintext = request.form['plaintext']
        
        # Load the RSA key
        key = serialization.load_pem_private_key(
            key_pem.encode(),
            password=None,
        )
        
        if action == 'Encrypt':
            ciphertext = key.public_key().encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result_message = ciphertext.hex()
        
        elif action == 'Decrypt':
            plaintext = key.decrypt(
                bytes.fromhex(plaintext),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result_message = plaintext.decode()
    
    return render_template('rsa.html', result_message=result_message)

@app.route('/sha', methods=['GET', 'POST'])
def sha():
    hashed_message = None
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        hashed_message = hashlib.sha256(plaintext.encode()).hexdigest()
    return render_template('sha.html', hashed_message=hashed_message)


@app.route('/substitution_cipher', methods=['GET', 'POST'])
def substitution_cipher():
    decrypted_message = None
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        key = request.form['key']
        
        # Example of a simple substitution cipher
        def decrypt(ciphertext, key):
            alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            key = key.upper()
            key_map = str.maketrans(key, alphabet)
            return ciphertext.translate(key_map)
        
        decrypted_message = decrypt(ciphertext, key)
    
    return render_template('substitution_cipher.html', decrypted_message=decrypted_message)


if __name__ == '__main__':
    app.run(debug=True)
