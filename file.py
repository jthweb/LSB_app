import streamlit as st
from PIL import Image
import io
import time
import os
import wave
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Configuration
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
AES_BLOCK_SIZE = 16
DELIMITER = b"__STEALTHGUARD_EOF__"

# --- Cryptography ---

def get_key_from_password(password, salt):
    """Derives a key from a password and salt using PBKDF2."""
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_data(data_bytes, password):
    """Encrypts byte data with AES-256 CBC, prepending a random salt and IV."""
    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data_bytes, AES_BLOCK_SIZE))
    return salt + cipher.iv + ciphertext

def decrypt_data(encrypted_data, password):
    """Decrypts data, returning None if the key is wrong or data is corrupt."""
    try:
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE + AES_BLOCK_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + AES_BLOCK_SIZE:]
        key = get_key_from_password(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, AES_BLOCK_SIZE)
    except (ValueError, KeyError, IndexError):
        return None

# --- Steganography Utilities ---

def data_to_binary(data):
    """Converts bytes to a binary string."""
    return ''.join(format(byte, '08b') for byte in data)

def binary_to_bytes(binary_str):
    """Converts a binary string back to bytes."""
    if len(binary_str) % 8 != 0:
        binary_str = binary_str[:-(len(binary_str) % 8)]
    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))

# --- Image Steganography ---

def hide_data_in_image(image, data):
    """Hides data within an image's LSBs."""
    binary_data = data_to_binary(data + DELIMITER)
    data_len = len(binary_data)
    
    if data_len > image.width * image.height * 3:
        raise ValueError("Secret is too large for this image.")

    img_data = list(image.getdata())
    new_img_data = []
    data_idx = 0
    
    for pixel in img_data:
        new_pixel = list(pixel)
        for i in range(3): # R, G, B
            if data_idx < data_len:
                new_pixel[i] = pixel[i] & 0b11111110 | int(binary_data[data_idx])
                data_idx += 1
        new_img_data.append(tuple(new_pixel))
    
    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_img_data)
    return new_image

def extract_data_from_image(image):
    """Extracts hidden data from an image's LSBs."""
    img_data = image.getdata()
    binary_data = ""
    delimiter_bin = data_to_binary(DELIMITER)
    
    for pixel in img_data:
        for i in range(3):
            binary_data += str(pixel[i] & 1)
        if delimiter_bin in binary_data:
            break
            
    delimiter_pos = binary_data.find(delimiter_bin)
    if delimiter_pos == -1:
        return None
        
    return binary_to_bytes(binary_data[:delimiter_pos])

# --- Audio Steganography ---

def hide_data_in_audio(audio_bytes, data):
    """Hides data within a WAV audio file's LSBs."""
    binary_data = data_to_binary(data + DELIMITER)
    data_len = len(binary_data)

    with wave.open(io.BytesIO(audio_bytes), 'rb') as wav_in:
        params = wav_in.getparams()
        frames = bytearray(wav_in.readframes(wav_in.getnframes()))

        if data_len > len(frames):
            raise ValueError("Secret is too large for this audio file.")

        for i in range(data_len):
            frames[i] = frames[i] & 0b11111110 | int(binary_data[i])

        with io.BytesIO() as buffer:
            with wave.open(buffer, 'wb') as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(bytes(frames))
            return buffer.getvalue()

def extract_data_from_audio(audio_bytes):
    """Extracts hidden data from a WAV audio file's LSBs."""
    with wave.open(io.BytesIO(audio_bytes), 'rb') as wav_in:
        frames = wav_in.readframes(wav_in.getnframes())
        binary_data = "".join([str(byte & 1) for byte in frames])
        
        delimiter_bin = data_to_binary(DELIMITER)
        delimiter_pos = binary_data.find(delimiter_bin)
        
        if delimiter_pos == -1:
            return None
        
        return binary_to_bytes(binary_data[:delimiter_pos])

# --- Streamlit UI ---

def main():
    st.set_page_config(page_title="StealthGuard Pro", page_icon=" Moin", layout="centered")

    # The new, "sicker" UI is defined here with CSS
    st.markdown("""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap');

            .stApp {
                background: #0f0c29;
                background: -webkit-linear-gradient(to right, #24243e, #302b63, #0f0c29);
                background: linear-gradient(to right, #24243e, #302b63, #0f0c29);
                animation: gradient 15s ease infinite;
                background-size: 400% 400%;
            }

            @keyframes gradient {
                0% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
                100% { background-position: 0% 50%; }
            }

            h1, h2, h3 {
                font-family: 'Orbitron', sans-serif;
                color: #00cyan;
                text-shadow: 0 0 10px #00c6ff, 0 0 20px #00c6ff, 0 0 30px #00c6ff;
            }
            
            /* Glassmorphism Container */
            [data-testid="stVerticalBlock"] > [style*="flex-direction: column;"] > [data-testid="stVerticalBlock"] {
                background: rgba(40, 40, 60, 0.6);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                padding: 25px;
                margin-top: 20px;
            }

            .stTabs [data-baseweb="tab-list"] { 
                gap: 24px; 
            }
            .stTabs [data-baseweb="tab"] {
                background-color: transparent;
                border-radius: 4px;
                padding: 10px 15px;
                transition: background-color 0.3s ease;
                border-bottom: 2px solid transparent;
            }
            .stTabs [aria-selected="true"] { 
                border-bottom: 2px solid #00c6ff;
                color: #00c6ff;
            }
            
            .stButton > button {
                border-radius: 8px;
                border: 1px solid #00c6ff;
                background-color: rgba(0, 198, 255, 0.1);
                color: #00c6ff;
                transition: all 0.3s ease-in-out;
                box-shadow: 0 0 5px #00c6ff;
            }
            .stButton > button:hover {
                box-shadow: 0 0 15px #00c6ff, 0 0 25px #00c6ff;
                transform: scale(1.05);
                background-color: rgba(0, 198, 255, 0.2);
            }
        </style>""", unsafe_allow_html=True)
    
    st.title("🛡️ STEALTHGUARD PRO")
    st.markdown("---")

    encode_tab, decode_tab = st.tabs(["[ CLOAK DATA ]", "[ REVEAL DATA ]"])

    with encode_tab:
        st.header("📦 1. Load Your Payload")
        secret_type = st.radio("What is the nature of your secret?", ["Text", "Image"], horizontal=True)

        secret_bytes = None
        if secret_type == "Text":
            message = st.text_area("Input secret message:", placeholder="The owl watches at dawn...")
            if message:
                secret_bytes = b"TXT:" + message.encode('utf-8')
        elif secret_type == "Image":
            secret_image_file = st.file_uploader("Upload secret image:", type=['png', 'jpg', 'jpeg'])
            if secret_image_file:
                file_ext = secret_image_file.name.split('.')[-1].upper()
                header = f"IMG:{file_ext}:".encode('utf-8')
                secret_bytes = header + secret_image_file.getvalue()

        st.header("🚢 2. Select Your Vessel")
        carrier_type = st.radio("Choose the medium to carry your payload:", ["Image", "Audio (.wav)"], horizontal=True)

        carrier_file = st.file_uploader(f"Upload carrier {carrier_type}:", type=['png', 'jpg', 'jpeg', 'bmp'] if carrier_type == "Image" else ['wav'])
        
        if st.button("Initiate Encoding Sequence", use_container_width=True):
            secret_key = os.environ.get('ENCRYPTION_KEY')
            if not secret_key:
                st.error("FATAL ERROR: ENCRYPTION_KEY not configured on server.")
            elif secret_bytes and carrier_file:
                try:
                    with st.status("Engaging Stealth Protocol...", expanded=True) as status:
                        status.write("🔐 Encrypting payload with AES-256...")
                        encrypted_data = encrypt_data(secret_bytes, secret_key)
                        time.sleep(1.5)

                        status.write(f"🧬 Weaving encrypted data into vessel's structure...")
                        output_bytes, fname, mime = (None, "encoded_output", "application/octet-stream")

                        if carrier_type == "Image":
                            carrier_image = Image.open(carrier_file).convert("RGB")
                            encoded_image = hide_data_in_image(carrier_image, encrypted_data)
                            buf = io.BytesIO()
                            encoded_image.save(buf, format="PNG")
                            output_bytes, fname, mime = buf.getvalue(), "encoded_image.png", "image/png"
                        
                        elif carrier_type == "Audio (.wav)":
                            output_bytes = hide_data_in_audio(carrier_file.getvalue(), encrypted_data)
                            fname, mime = "encoded_audio.wav", "audio/wav"
                        
                        time.sleep(1.5)
                        status.update(label="✅ Encoding Complete. Vessel is ready.", state="complete")
                    
                    st.success("Encoding successful!")
                    st.download_button("Download Secure Vessel", output_bytes, fname, mime, use_container_width=True)

                except ValueError as e:
                    st.error(f"⚠️ Process Halted: {e}")
                except Exception as e:
                    st.error(f"💥 System Malfunction: {e}")
            else:
                st.warning("Awaiting input: Payload and Vessel required to proceed.")

    with decode_tab:
        st.header("📂 1. Upload Secure Vessel")
        carrier_type_decode = st.radio("Specify vessel type:", ["Image", "Audio (.wav)"], horizontal=True, key="decode_carrier_type")
        carrier_file_decode = st.file_uploader(f"Upload encoded {carrier_type_decode}:", type=['png'] if carrier_type_decode == "Image" else ['wav'], key="decode_uploader")

        st.header("🔑 2. Provide Decryption Key")
        decryption_key = st.text_input("Enter the master key to unlock the payload:", type="password")

        if st.button("Initiate Decoding Sequence", use_container_width=True):
            if carrier_file_decode and decryption_key:
                try:
                    with st.status("Analyzing vessel integrity...", expanded=True) as status:
                        status.write(f"🔬 Scanning for hidden data signatures...")
                        extracted_data = None
                        if carrier_type_decode == "Image":
                            img = Image.open(carrier_file_decode)
                            extracted_data = extract_data_from_image(img)
                        elif carrier_type_decode == "Audio (.wav)":
                            extracted_data = extract_data_from_audio(carrier_file_decode.getvalue())
                        
                        time.sleep(1.5)
                        if not extracted_data:
                            raise ValueError("Scan negative. No data signature found.")

                        status.write("🔑 Key accepted. Attempting payload decryption...")
                        decrypted_bytes = decrypt_data(extracted_data, decryption_key)
                        time.sleep(1.5)
                        if not decrypted_bytes:
                            raise ValueError("Decryption failed. Key is incorrect or data is corrupt.")

                        status.update(label="✅ Payload Extracted Successfully.", state="complete")

                    st.success("Mission Accomplished!")
                    
                    if decrypted_bytes.startswith(b"TXT:"):
                        st.subheader("--- DECODED TRANSMISSION ---")
                        st.text_area("Message:", decrypted_bytes[4:].decode('utf-8'), height=150)
                    elif decrypted_bytes.startswith(b"IMG:"):
                        st.subheader("--- RECOVERED ASSET ---")
                        parts = decrypted_bytes.split(b':', 2)
                        img_ext = parts[1].decode('utf-8').lower()
                        img_bytes = parts[2]
                        st.image(img_bytes, caption=f"Recovered Image (. {img_ext})")

                except ValueError as e:
                    st.error(f"⚠️ Mission Failed: {e}")
                except Exception as e:
                    st.error(f"💥 Critical Error: {e}")
            else:
                st.warning("Awaiting input: Vessel and Key required to proceed.")

if __name__ == '__main__':
    main()

