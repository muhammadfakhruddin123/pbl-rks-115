from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from PIL import Image
import numpy as np
import os
import io
import zlib
from functools import wraps
import random

# Memuat variabel lingkungan
load_dotenv()

# Setup Flask
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Konfigurasi MySQL
app.config["MYSQL_HOST"] = os.getenv("MYSQL_HOST", "localhost")
app.config["MYSQL_USER"] = os.getenv("MYSQL_USER", "flaskuser")
app.config["MYSQL_PASSWORD"] = os.getenv("MYSQL_PASSWORD", "new_password")
app.config["MYSQL_DB"] = os.getenv("MYSQL_DB", "steganografi_db")

# Inisialisasi MySQL dan Bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Menghasilkan atau memuat kunci enkripsi
def load_or_generate_key():
    key_path = "secret.key"
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        return key

key = Fernet(load_or_generate_key())

# Dekorator untuk halaman yang membutuhkan login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Anda harus login terlebih dahulu.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET"])
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

# Game CTF Functions
def encrypt_caesar(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def generate_encrypted_flag():
    flag = "CTF{SolveTheCipher}"
    shift = random.randint(1, 25)
    encrypted_flag = encrypt_caesar(flag, shift)
    return encrypted_flag, shift, flag

@app.route("/game")
@login_required
def game():
    encrypted_flag, shift, flag = generate_encrypted_flag()
    session["shift"] = shift
    session["flag"] = flag
    return render_template("game.html", encrypted_flag=encrypted_flag)

@app.route("/check_guess", methods=["POST"])
@login_required
def check_guess():
    user_guess = request.json.get("guess", "")
    if user_guess == session["flag"]:
        return jsonify({"success": True, "message": "Selamat! Anda berhasil memecahkan pesan dan menemukan flag!"})
    else:
        return jsonify({"success": False, "message": "Salah! Coba lagi."})

# Steganography Functions
def resize_image(image_file, max_width=800, max_height=800):
    img = Image.open(image_file)
    img.thumbnail((max_width, max_height))
    return img

def compress_and_encrypt_message(message, key):
    compressed_message = zlib.compress(message.encode())
    encrypted_message = key.encrypt(compressed_message)
    return encrypted_message

def hide_message_in_image(image_file, message, key):
    img = resize_image(image_file)
    encrypted_message = compress_and_encrypt_message(message, key)
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
    
    img_array = np.array(img)
    flat_array = img_array.flatten()

    if len(binary_message) > len(flat_array):
        return None, "Pesan terlalu besar untuk disembunyikan dalam gambar ini."

    for i in range(len(binary_message)):
        flat_array[i] = (flat_array[i] & 0xFE) | int(binary_message[i])
    
    encoded_array = flat_array.reshape(img_array.shape)
    encoded_image = Image.fromarray(encoded_array.astype('uint8'))
    buffer = io.BytesIO()
    encoded_image.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer, None

def extract_message_from_image(image_file, key):
    img = Image.open(image_file)
    img_array = np.array(img)
    flat_array = img_array.flatten()

    binary_message = ""
    for byte in flat_array:
        binary_message += str(byte & 1)

    byte_message = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
    byte_message = [int(b, 2) for b in byte_message]
    encrypted_message = bytes(byte_message)

    try:
        decrypted_message = zlib.decompress(key.decrypt(encrypted_message)).decode()
        return decrypted_message
    except Exception:
        return None

@app.route("/encode", methods=["POST"])
@login_required
def encode():
    if "image" not in request.files:
        return "Tidak ada file yang diunggah", 400

    file = request.files["image"]
    message = request.form["message"]

    encoded_image, error = hide_message_in_image(file, message, key)
    if error:
        return error, 400

    encoded_image_path = "static/encoded_image.png"
    with open(encoded_image_path, "wb") as f:
        f.write(encoded_image.getvalue())
    return redirect(url_for("result", image_path=encoded_image_path))

@app.route("/decode", methods=["POST"])
@login_required
def decode():
    if "image" not in request.files:
        return "Tidak ada file yang diunggah", 400

    file = request.files["image"]
    decoded_message = extract_message_from_image(file, key)

    if decoded_message is None:
        return "Gagal mendekode pesan.", 400

    return render_template("result.html", decoded_message=decoded_message)

@app.route("/result")
@login_required
def result():
    image_path = request.args.get("image_path", None)
    decoded_message = request.args.get("decoded_message", None)
    return render_template("result.html", image_path=image_path, decoded_message=decoded_message)

if __name__ == "__main__":
    app.run(debug=True)
