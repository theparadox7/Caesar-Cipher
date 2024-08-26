from flask import Flask, render_template, request

app = Flask(__name__)

def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            decrypted_char = chr((ord(char) - offset - shift) % 26 + offset)
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

@app.route("/", methods=["GET", "POST"])
def index():
    decrypted_message = ""
    ciphertext = ""
    shift = ""
    if request.method == "POST":
        ciphertext = request.form.get("ciphertext")
        shift = request.form.get("shift")
        if ciphertext and shift.isdigit():
            shift = int(shift)
            decrypted_message = caesar_decrypt(ciphertext, shift)
    return render_template("index.html", ciphertext=ciphertext, shift=shift, decrypted_message=decrypted_message)

if __name__ == "__main__":
    app.run(debug=True)
