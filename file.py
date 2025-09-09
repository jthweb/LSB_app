import streamlit as st
from PIL import Image
import io
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# --- Configuration ---
SALT_SIZE = 16
KEY_SIZE = 32  # 256-bit key
ITERATIONS = 100000
AES_BLOCK_SIZE = 16
DELIMITER = b"__EOF__"

# --- Cryptography Functions ---

def get_key_from_password(password, salt):
    """Derives a key from a password and salt using PBKDF2."""
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_message(message, password):
    """
    Encrypts a message with AES-256 CBC using a password-derived key.
    A new random salt is generated for each encryption.
    """
    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    message_bytes = message.encode('utf-8')
    ciphertext = cipher.encrypt(pad(message_bytes, AES_BLOCK_SIZE))
    # Prepend salt and IV to the ciphertext
    return salt + cipher.iv + ciphertext

def decrypt_message(encrypted_data, password):
    """Decrypts data encrypted with AES-256 CBC using a user-provided password."""
    try:
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE + AES_BLOCK_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + AES_BLOCK_SIZE:]
        
        key = get_key_from_password(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        decrypted_padded_message = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded_message, AES_BLOCK_SIZE)
        return decrypted_message.decode('utf-8')
    except (ValueError, KeyError, IndexError):
        return None

# --- Steganography Functions (Unchanged) ---

def data_to_binary(data):
    """Converts bytes to a binary string."""
    return ''.join(format(byte, '08b') for byte in data)

def hide_data_in_image(image, data):
    """Hides binary data within an image using the LSB technique."""
    data_with_delimiter = data_to_binary(data + DELIMITER)
    data_len = len(data_with_delimiter)
    
    img_data = image.getdata()
    width, height = image.size
    max_bytes = width * height * 3 // 8
    
    if data_len > max_bytes * 8:
        raise ValueError("Message is too large for this image.")

    new_img_data = []
    data_index = 0
    
    for pixel in img_data:
        if data_index < data_len:
            new_pixel = list(pixel)
            for i in range(3):
                if data_index < data_len:
                    new_pixel[i] = pixel[i] & ~1 | int(data_with_delimiter[data_index])
                    data_index += 1
            new_img_data.append(tuple(new_pixel))
        else:
            new_img_data.append(pixel)
            
    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_img_data)
    return new_image

def extract_data_from_image(image):
    """Extracts hidden data from an image."""
    img_data = image.getdata()
    binary_data = ""
    delimiter_bin = data_to_binary(DELIMITER)
    
    for pixel in img_data:
        for i in range(3):
            binary_data += str(pixel[i] & 1)
        if delimiter_bin in binary_data:
            data_end_index = binary_data.find(delimiter_bin)
            binary_data = binary_data[:data_end_index]
            break
    
    if not binary_data: return None

    all_bytes = bytearray(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8) if len(binary_data[i:i+8]) == 8)
    return bytes(all_bytes)

# --- Streamlit UI ---

def main():
    st.set_page_config(page_title="StealthGuard LSB", page_icon="🛡️", layout="centered")

    st.markdown("""
        <style>
            .stApp {
                background-color: #111827;
                background-image: radial-gradient(circle at 1px 1px, #374151 1px, transparent 0);
                background-size: 20px 20px;
            }
            .stTabs [data-baseweb="tab-list"] { gap: 24px; }
            .stTabs [data-baseweb="tab"] {
                height: 50px; white-space: pre-wrap; background-color: transparent;
                border-radius: 4px 4px 0px 0px; gap: 1px; padding-top: 10px; padding-bottom: 10px;
            }
            .stTabs [aria-selected="true"] { background-color: #059669; color: white; }
            h1 { color: #059669; text-shadow: 0 0 5px #059669, 0 0 10px #059669; }
        </style>""", unsafe_allow_html=True)

    st.title("🛡️ StealthGuard LSB")
    st.markdown("Encrypt messages with a secret key and hide them in images.")

    encode_tab, decode_tab = st.tabs(["Encode Message", "Decode Message"])

    with encode_tab:
        st.subheader("1. Upload Image")
        uploaded_image = st.file_uploader("Choose an image file", type=['png', 'jpg', 'jpeg', 'bmp'], key="encode_uploader")

        st.subheader("2. Secret Message")
        message = st.text_area("Enter the message you want to hide", key="encode_message")
        
        # Fetch the secret key from environment variables
        secret_key = os.environ.get('ENCRYPTION_KEY')

        if st.button("Encode & Prepare Download", use_container_width=True, type="primary"):
            if not secret_key:
                st.error("FATAL: ENCRYPTION_KEY environment variable is not set. The app cannot encrypt messages.")
            elif uploaded_image and message:
                try:
                    image = Image.open(uploaded_image).convert("RGB")
                    
                    with st.status("Starting encoding process...", expanded=True) as status:
                        status.write("Using secure environment key for encryption...")
                        time.sleep(1)
                        encrypted_message = encrypt_message(message, secret_key)

                        status.write("Embedding encrypted data into image pixels...")
                        encoded_image = hide_data_in_image(image, encrypted_message)
                        time.sleep(1)
                        
                        status.update(label="Encoding complete!", state="complete", expanded=False)

                    buf = io.BytesIO()
                    encoded_image.save(buf, format="PNG")
                    st.success("Image encoded successfully!")
                    st.image(encoded_image, caption="Encoded Image Preview", use_container_width=True)
                    st.download_button(
                        label="Download Encoded Image", data=buf.getvalue(),
                        file_name="encoded_image.png", mime="image/png", use_container_width=True
                    )
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")
            else:
                st.warning("Please provide an image and a message.")


    with decode_tab:
        st.subheader("1. Upload Encoded Image")
        encoded_file = st.file_uploader("Choose an image with a hidden message", type=['png'], key="decode_uploader")
        
        st.subheader("2. Enter Decryption Key")
        decryption_key = st.text_input("The key is required to unlock the message", type="password", key="decryption_key")

        if st.button("Decode Message", use_container_width=True, type="primary"):
            if encoded_file and decryption_key:
                try:
                    image = Image.open(encoded_file).convert("RGB")
                    
                    with st.status("Starting decoding process...", expanded=True) as status:
                        status.write("Extracting encrypted data from pixels...")
                        extracted_data = extract_data_from_image(image)
                        time.sleep(1)

                        if not extracted_data:
                            status.update(label="Decoding Failed!", state="error")
                            st.error("No hidden message found or data is corrupted.")
                        else:
                            status.write("Attempting to decrypt with provided key...")
                            decrypted_message = decrypt_message(extracted_data, decryption_key)
                            time.sleep(1)

                            if not decrypted_message:
                                status.update(label="Decoding Failed!", state="error")
                                st.error("Decryption failed. The key is incorrect or the data is corrupt.")
                            else:
                                status.update(label="Decoding complete!", state="complete")
                                st.success("Message decoded successfully!")
                                st.text_area("Decoded Message:", decrypted_message, height=150)
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")
            else:
                st.warning("Please provide an encoded image and the decryption key.")

if __name__ == '__main__':
    main()

