from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from PIL import Image
import numpy as np
import os
import io
import zlib
from functools import wraps

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

# Route untuk Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Cek jika password tidak cocok
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))
        
        # Cek jika username sudah ada
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))

        # Enkripsi password menggunakan bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        mysql.connection.commit()
        flash("Registration successful!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Route untuk Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Verifikasi pengguna dan password dengan database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):  # Mengecek hash password
            session["username"] = username
            flash("Login berhasil!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Username atau password salah!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

# Route untuk Logout
@app.route("/logout")
@login_required
def logout():
    # Menghapus data sesi yang terkait dengan pengguna
    session.pop("username", None)
    flash("Anda telah logout", "success")
    return redirect(url_for("login"))

# Steganography Functions
def resize_image(image_file, max_width=800, max_height=800):
    img = Image.open(image_file)
    img.thumbnail((max_width, max_height))
    return img

def compress_and_encrypt_message(message, key):
    # Menyandi pesan dengan enkripsi Fernet
    compressed_message = zlib.compress(message.encode())
    encrypted_message = key.encrypt(compressed_message)
    return encrypted_message

def extract_message_from_image(image_file, key):
    # Mengambil data yang disembunyikan dari gambar
    img = Image.open(image_file)
    img_array = np.array(img)
    flat_array = img_array.flatten()

    binary_message = ""
    for pixel in flat_array:
        binary_message += str(pixel & 1)

    encrypted_message = bytearray(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8))
    try:
        decompressed_message = zlib.decompress(key.decrypt(encrypted_message))
        return decompressed_message.decode()
    except Exception as e:
        return None

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

# Route untuk halaman Steganografi
@app.route('/steganografi')
def steganografi():
    return render_template('index.html')

@app.route("/steganografi/encode", methods=["POST"])
@login_required
def encode():
    if "image" not in request.files:
        flash("Tidak ada file yang diunggah", "danger")
        return redirect(url_for("steganografi"))

    file = request.files["image"]
    message = request.form["message"]

    encoded_image, error = hide_message_in_image(file, message, key)
    if error:
        flash(error, "danger")
        return redirect(url_for("steganografi"))

    encoded_image_path = os.path.join("static", "encoded_image.png")
    with open(encoded_image_path, "wb") as f:
        f.write(encoded_image.getvalue())

    flash("Pesan berhasil disembunyikan dalam gambar!", "success")
    return redirect(url_for("stegano_result", image_path="encoded_image.png"))

@app.route("/steganografi/decode", methods=["POST"])
@login_required
def decode():
    if "image" not in request.files:
        flash("Tidak ada file yang diunggah", "danger")
        return redirect(url_for("steganografi"))

    file = request.files["image"]
    decoded_message = extract_message_from_image(file, key)

    if decoded_message is None:
        flash("Gagal mendekode pesan.", "danger")
        return redirect(url_for("steganografi"))

    return redirect(url_for("stegano_result", decoded_message=decoded_message))

@app.route("/steganografi/result")
@login_required
def stegano_result():
    image_path = request.args.get("image_path", None)
    decoded_message = request.args.get("decoded_message", None)
    return render_template("result.html", image_path=image_path, decoded_message=decoded_message)

# Route untuk halaman CTF Game
@app.route("/game")
@login_required
def game_home():
    return render_template("game.html")

if __name__ == "__main__":
    app.run(debug=True)
