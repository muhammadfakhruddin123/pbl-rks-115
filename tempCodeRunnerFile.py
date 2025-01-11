from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from PIL import Image
import numpy as np
import os
import io
import zlib
import random
from functools import wraps
from cryptography.fernet import Fernet

# Memuat kunci dari variabel lingkungan
fernet_key = os.getenv("FERNET_KEY")

# Jika kunci tidak ditemukan, buat kunci baru
if not fernet_key:
    fernet_key = Fernet.generate_key()

# Inisialisasi objek fernet
fernet = Fernet(fernet_key)

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

# Fungsi utilitas untuk kompresi dan enkripsi pesan
def compress_and_encrypt_message(message, key):
    compressed_message = zlib.compress(message.encode())
    encrypted_message = key.encrypt(compressed_message)
    return encrypted_message

# Fungsi untuk dekripsi dan dekompresi pesan
def decrypt_and_decompress_message(encrypted_message, key):
    decrypted_message = key.decrypt(encrypted_message)
    decompressed_message = zlib.decompress(decrypted_message).decode()
    return decompressed_message

# Fungsi untuk meresize gambar
def resize_image(image_file, max_width=800, max_height=800):
    img = Image.open(image_file)
    img.thumbnail((max_width, max_height))
    return img

# Fungsi untuk menyembunyikan pesan dalam gambar
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

# Fungsi untuk mengekstrak pesan dari gambar
def extract_message_from_image(image_file, key):
    img = Image.open(image_file)
    img_array = np.array(img)
    flat_array = img_array.flatten()

    binary_message = ''.join(str(flat_array[i] & 1) for i in range(len(flat_array)))
    byte_message = bytearray()
    for i in range(0, len(binary_message), 8):
        byte_message.append(int(binary_message[i:i+8], 2))

    try:
        return decrypt_and_decompress_message(bytes(byte_message), key)
    except Exception:
        return None

# Dekorator untuk halaman yang membutuhkan login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Anda harus login terlebih dahulu.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Function to encrypt with Caesar Cipher
def encrypt_caesar(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

# Generate encrypted flag
flag = "CTF{SolveTheCipher}"
shift = random.randint(1, 25)  # You can set this to a fixed value to ensure consistency
encrypted_flag = encrypt_caesar(flag, shift)

# Fungsi untuk mendapatkan hint acak untuk CTF
def get_random_hint(level="easy"):
    easy_hints = [
        "Pergeseran dihitung dengan mengurangi 7 dari 15.",
        "Jumlahkan 8 karakter untuk mendapatkan pergeseran.",
        "IP Address 192.168.1.1: jumlahkan 168 + 1 + 1 untuk pergeseran.",
        "Hasil XOR antara 9 dan 4 adalah pergeseran."
    ]
    
    medium_hints = [
        "RSA: n = 91, e = 5, temukan d dengan \( e \cdot d \mod (n-1) = 1 \).",
        "Hash MD5 dari 'password123' menghasilkan angka 81. Gunakan hasil modulo 26.",
        "AES Key 16 byte: hitung jumlah bit dan gunakan modulo 10.",
        "DES Key 64 bit: hitung panjang masing-masing bagian dalam bit."
    ]
    
    hard_hints = [
        "Diffie-Hellman: g = 3, p = 17, hasil \( g^3 \mod p \) adalah pergeseran.",
        "XOR: kunci 0xAC dengan 0x7F menghasilkan pergeseran.",
        "AES Key '1234abcd': konversi ke hex dan hitung modulo 8.",
        "Bcrypt salt 16 byte: gunakan panjang output hash.",
        "Cipher stream dengan kunci 128 bit dan pesan 256 bit: jumlah blok adalah pergeseran."
    ]
    
    if level == "easy":
        return random.choice(easy_hints)
    elif level == "medium":
        return random.choice(medium_hints)
    elif level == "hard":
        return random.choice(hard_hints)
    else:
        return random.choice(easy_hints)

@app.route('/get_hint')
def get_hint():
    level = request.args.get('level', 'easy')
    hint = get_random_hint(level)
    return jsonify({'hint': hint})

@app.route("/submit_ctf", methods=['POST'])
def submit_ctf():
    answer = request.form['answer']  # Ambil jawaban dari form
    print(f"Jawaban yang dimasukkan: {answer}")  # Menampilkan jawaban untuk debugging
    correct_answer = 'SolveTheCipher'  # Jawaban yang benar
    
    # Cek apakah jawaban yang dimasukkan benar
    if answer.strip().lower() == correct_answer.lower():
        flash('Jawaban Anda benar!', 'success')
    else:
        flash('Jawaban Anda salah, coba lagi!', 'danger')
    
    return redirect(url_for('ctf_game'))

@app.route("/ctf_game", methods=["GET", "POST"])
@login_required
def ctf_game():
    # Set soal yang terenkripsi secara tetap
    flag = "CTF{SolveTheCipher}"
    shift = random.randint(1, 25)  # Untuk mengacak pergeseran, atau bisa diganti nilai tetap
    encrypted_flag = encrypt_caesar(flag, shift)  # Enkripsi soal dengan Caesar Cipher

    # Menghasilkan petunjuk yang sesuai dengan pergeseran
    hint = get_hint_for_shift(shift)  # Fungsi untuk membuat petunjuk berdasarkan pergeseran

    result_message = None
    result_class = None
    if request.method == "POST":
        answer = request.form.get("answer", "")
        correct_answer = 'SolveTheCipher'  # Jawaban yang benar dari soal CTF

        # Verifikasi jawaban
        if answer.strip().lower() == correct_answer.lower():
            result_message = "Jawaban Anda benar! Selamat!"
            result_class = "success"
        else:
            result_message = "Jawaban Anda salah, coba lagi!"
            result_class = "danger"

    return render_template(
        "game.html", 
        encrypted_message=encrypted_flag, 
        hint=hint, 
        result_message=result_message, 
        result_class=result_class
    )

# Fungsi untuk menghasilkan petunjuk berdasarkan pergeseran Caesar Cipher
def get_hint_for_shift(shift):
    # Petunjuk terkait pergeseran
    return f"Gunakan Caesar Cipher dengan pergeseran {shift}. Coba gunakan pergeseran ini untuk mengungkap pesan tersembunyi."

@app.route("/steganografi")
@login_required
def steganografi():
    return render_template("index.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            mysql.connection.commit()
            cursor.close()
            flash("Registrasi berhasil! Silakan login.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.check_password_hash(user[2], password):
            session["username"] = user[1]
            flash("Login berhasil!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Username atau password salah.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logout berhasil.", "info")
    return redirect(url_for("login"))

@app.route("/encode", methods=["POST"])
@login_required
def encode():
    if "image" not in request.files:
        return "Tidak ada file yang diunggah", 400

    file = request.files["image"]
    message = request.form["message"]

    # Menyembunyikan pesan dalam gambar
    encoded_image, error = hide_message_in_image(file, message, fernet)  # Menggunakan fernet untuk enkripsi
    if error:
        return error, 400

    # Simpan gambar hasil encode
    encoded_image_path = "static/encoded_image.png"
    with open(encoded_image_path, "wb") as f:
        f.write(encoded_image.getvalue())
    
    # Mengarahkan ke halaman hasil dengan path gambar terencode
    return redirect(url_for("result", image_path=encoded_image_path))

@app.route("/decode", methods=["POST"])
@login_required
def decode():
    if "image" not in request.files:
        return "Tidak ada file yang diunggah", 400

    file = request.files["image"]
    decoded_message = extract_message_from_image(file, fernet)  # Menggunakan fernet untuk dekripsi

    if decoded_message is None:
        return "Gagal mendekode pesan.", 400

    # Mengarahkan ke halaman hasil dengan pesan yang didekode
    return redirect(url_for("result", decoded_message=decoded_message))

@app.route("/result")
@login_required
def result():
    image_path = request.args.get("image_path", None)
    decoded_message = request.args.get("decoded_message", None)
    return render_template("result.html", image_path=image_path, decoded_message=decoded_message)

@app.route("/")
def index():
    # Jika sudah login, arahkan ke dashboard
    if "username" in session:
        return redirect(url_for("dashboard"))
    # Jika belum login, arahkan ke halaman login
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
