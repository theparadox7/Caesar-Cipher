from flask import Flask, render_template, request

app = Flask(__name__)

def caesar_decrypt(ciphertext, shift):
    # Caesar Cipher Decryption Logic
    ...

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

@app.route("/substitution_cipher")
def substitution_cipher():
    return render_template("substitution_cipher.html")

@app.route("/rsa")
def rsa():
    return render_template("rsa.html")

@app.route("/md5")
def md5():
    return render_template("md5.html")

@app.route("/sha")
def sha():
    return render_template("sha.html")

if __name__ == "__main__":
    app.run(debug=True)
