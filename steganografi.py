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
from cryptography.fernet import Fernet

def encrypt_caesar(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

fernet_key = os.getenv("FERNET_KEY")

if not fernet_key:
    fernet_key = Fernet.generate_key()

# Inisialisasi objek fernet
fernet = Fernet(fernet_key)

# Memuat variabel lingkungan
load_dotenv()

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

# Menambahkan pemeriksaan ukuran gambar yang cukup besar untuk menampung pesan terenkripsi
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
    try:
        img = Image.open(image_file)
        img_array = np.array(img)
        flat_array = img_array.flatten()

        print(f"Image array size: {img_array.shape}")
        print(f"Flattened image array length: {len(flat_array)}") 

        # Ekstraksi bit dari gambar
        binary_message = ''.join(str(flat_array[i] & 1) for i in range(len(flat_array)))

        print(f"Extracted binary message length: {len(binary_message)}") 

        # Menyusun kembali pesan dalam byte
        byte_message = bytearray()
        for i in range(0, len(binary_message), 8):
            byte_message.append(int(binary_message[i:i+8], 2))

        print(f"Extracted byte message length: {len(byte_message)}") 

        # Dekripsi dan dekompresi pesan
        decrypted_message = decrypt_and_decompress_message(bytes(byte_message), key)
        print(f"Decrypted message: {decrypted_message}") 
        return decrypted_message
    except Exception as e:
        print(f"Error during message extraction: {e}")
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Anda harus login terlebih dahulu.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

questions = [
    {"question": "CTF{MysteryFormula}", "shift": 2, "hint": "sebuah balok telah diukur dan ternyata panjangnya adalah 10,3 cm dan lebarnya 6,5 cm berapa angka penting yang ada dalam luas balok?."},
    {"question": "CTF{HiddenSum}", "shift": 19, "hint": "Jumlahkan angka-angka yang berada di posisi yang merupakan angka pertama dari setiap bilangan prima dalam urutan genap."},
    {"question": "CTF{LogarithmicChallenge}", "shift": 20, "hint": "Diberikan logaritma natural ln(x) = 3, temukan nilai x."},
    {"question": "CTF{MysteriousSequence}", "shift": 25, "hint": "Dalam deret angka ini: 1, 4, 9, 16, ... Temukan angka berikutnya jika pola ini berlanjut."},
    {"question": "CTF{MathematicalPuzzle}", "shift": 4, "hint": "Temukan angka yang memenuhi persamaan berikut: (x + 2)^2 = 36 dan x > 0."},
    {"question": "CTF{PrimeSum}", "shift": 16, "hint": "Temukan jumlah dari dua bilangan prima terkecil yang menghasilkan hasil kali lebih besar dari 50."},
]

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
    encoded_image, error = hide_message_in_image(file, message, fernet) 
    if error:
        return error, 400

    # Simpan gambar hasil encode ke folder static
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
    decoded_message = extract_message_from_image(file, fernet) 

    if decoded_message is None:
        return "Gagal mendekode pesan. Periksa file gambar dan coba lagi.", 400

    return redirect(url_for("result", decoded_message=decoded_message))

@app.route("/result")
@login_required
def result():
    image_path = request.args.get("image_path", None)
    decoded_message = request.args.get("decoded_message", None)
    return render_template("result.html", image_path=image_path, decoded_message=decoded_message)

@app.route("/ctf-game", methods=["GET", "POST"])
@login_required
def ctf_game():

    current_question_idx = session.get('current_question_idx', 0)
    current_question = questions[current_question_idx]

    encrypted_message = encrypt_caesar(current_question["question"], current_question["shift"])

    if request.method == "POST":
        answer = request.form["answer"]
        correct_answer = current_question["shift"]

        if int(answer) == correct_answer:
            flash("Jawaban benar!", "success")
            
            # Simpan index soal berikutnya ke session
            next_question_idx = current_question_idx + 1
            if next_question_idx < len(questions):
                session['current_question_idx'] = next_question_idx
            else:
                flash("Selamat, kamu telah menyelesaikan semua soal CTF!", "success")
                session.pop('current_question_idx', None) 
                return redirect(url_for('dashboard'))  # Arahkan kembali ke dashboard
            
            return redirect(url_for("ctf_game")) 
        else:
            flash("Jawaban salah! Coba lagi.", "danger")
    
    return render_template("game.html", question=current_question, encrypted_message=encrypted_message)

@app.route("/")
def index():
    # Jika sudah login, arahkan ke dashboard
    if "username" in session:
        return redirect(url_for("dashboard"))
    # Jika belum login, arahkan ke halaman login
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
