from PIL import Image
from Crypto.Cipher import AES
import base64

# Fungsi untuk menyisipkan pesan ke dalam gambar
def hide_message(image_path, output_path, message, key):
    # Enkripsi pesan
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    padded_message = message + (16 - len(message) % 16) * " "
    encrypted_message = base64.b64encode(cipher.encrypt(padded_message.encode())).decode("utf-8")

    # Buka gambar
    img = Image.open(image_path)
    binary_message = "".join(format(ord(char), "08b") for char in (encrypted_message + "#####"))
    pixels = img.load()

    # Modifikasi piksel
    idx = 0
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            if idx < len(binary_message):
                r, g, b = pixels[i, j]
                r = (r & ~1) | int(binary_message[idx])
                idx += 1
                pixels[i, j] = (r, g, b)
            else:
                break
    img.save(output_path)

# Fungsi untuk mengekstrak pesan dari gambar
def extract_message(image_path, key):
    img = Image.open(image_path)
    binary_data = ""
    pixels = img.load()

    for i in range(img.size[0]):
        for j in range(img.size[1]):
            r, _, _ = pixels[i, j]
            binary_data += str(r & 1)

    # Ubah data biner ke string
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-5:] == "#####":  # Delimiter
            break

    encrypted_message = decoded_data[:-5]

    # Dekripsi pesan
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message)).decode("utf-8")
    return decrypted_message.strip()
