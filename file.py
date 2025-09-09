import streamlit as st
from PIL import Image
import io
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

# --- Configuration ---
SALT_SIZE = 16
KEY_SIZE = 32  # 256-bit key
ITERATIONS = 100000
AES_BLOCK_SIZE = 16
DELIMITER = b"__EOF__"
# This internal secret key replaces the user-provided password.
# In a real-world scenario, this should be managed securely (e.g., environment variables).
SECRET_KEY = "stealthguard_internal_!@#_secret_key_&^%"

# --- Cryptography Functions ---

def get_key_from_password(password, salt):
    """Derives a key from a password and salt using PBKDF2."""
    return PBKDF2(password.encode(), salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_message(message, password):
    """
    Encrypts a message with AES-256 CBC. A new random salt and IV are used for
    each encryption, ensuring that encrypting the same message twice will
    result in different ciphertexts.
    """
    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC) # IV is generated automatically
    message_bytes = message.encode('utf-8')
    ciphertext = cipher.encrypt(pad(message_bytes, AES_BLOCK_SIZE))
    # The salt and IV are prepended to the ciphertext for use in decryption.
    return salt + cipher.iv + ciphertext

def decrypt_message(encrypted_data, password):
    """Decrypts data encrypted with AES-256 CBC."""
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

# --- Steganography Functions ---

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
        raise ValueError("Message is too large to hide in the given image.")

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
    
    if not binary_data:
        return None

    all_bytes = bytearray()
    for i in range(0, len(binary_data), 8):
        byte_chunk = binary_data[i:i+8]
        if len(byte_chunk) == 8:
            all_bytes.append(int(byte_chunk, 2))
            
    return bytes(all_bytes)

# --- Streamlit UI ---

def main():
    st.set_page_config(
        page_title="StealthGuard LSB",
        page_icon="🛡️",
        layout="centered",
    )

    # Custom CSS for the "sick look"
    st.markdown("""
        <style>
            .stApp {
                background-color: #111827;
                background-image: radial-gradient(circle at 1px 1px, #374151 1px, transparent 0);
                background-size: 20px 20px;
            }
            .stTabs [data-baseweb="tab-list"] {
                gap: 24px;
            }
            .stTabs [data-baseweb="tab"] {
                height: 50px;
                white-space: pre-wrap;
                background-color: transparent;
                border-radius: 4px 4px 0px 0px;
                gap: 1px;
                padding-top: 10px;
                padding-bottom: 10px;
            }
            .stTabs [aria-selected="true"] {
                background-color: #059669;
                color: white;
            }
            h1 {
                color: #059669;
                text-shadow: 0 0 5px #059669, 0 0 10px #059669;
            }
        </style>""", unsafe_allow_html=True)

    st.title("🛡️ StealthGuard LSB")
    st.markdown("Securely embed and extract secret messages in images.")

    encode_tab, decode_tab = st.tabs(["Encode Message", "Decode Message"])

    with encode_tab:
        st.subheader("1. Upload Image")
        uploaded_image = st.file_uploader("Choose an image file", type=['png', 'jpg', 'jpeg', 'bmp'], key="encode_uploader")

        st.subheader("2. Secret Message")
        message = st.text_area("Enter the message you want to hide", key="encode_message")
        
        if st.button("Encode & Prepare Download", use_container_width=True, type="primary"):
            if uploaded_image and message:
                try:
                    image = Image.open(uploaded_image).convert("RGB")
                    
                    with st.status("Starting encoding process...", expanded=True) as status:
                        status.write("Generating SHA-256 hash of the message...")
                        # This hash is for display/verification, not direct encryption.
                        h = hashlib.sha256(message.encode()).hexdigest()
                        time.sleep(1) 

                        status.write(f"Message hash: {h[:20]}...")
                        time.sleep(1)

                        status.write("Encrypting message with AES-256 using a unique salt and IV...")
                        encrypted_message = encrypt_message(message, SECRET_KEY)
                        time.sleep(1)

                        status.write("Embedding encrypted data into image pixels (LSB)...")
                        encoded_image = hide_data_in_image(image, encrypted_message)
                        time.sleep(1)
                        
                        status.update(label="Encoding complete!", state="complete", expanded=False)

                    # Save image to a byte stream
                    buf = io.BytesIO()
                    encoded_image.save(buf, format="PNG")
                    byte_im = buf.getvalue()
                    
                    st.success("Image encoded successfully!")
                    st.image(encoded_image, caption="Encoded Image Preview", use_container_width=True)
                    
                    st.download_button(
                        label="Download Encoded Image",
                        data=byte_im,
                        file_name="encoded_image.png",
                        mime="image/png",
                        use_container_width=True
                    )

                except ValueError as e:
                    st.error(f"Error: {e}")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")
            else:
                st.warning("Please provide an image and a message.")


    with decode_tab:
        st.subheader("1. Upload Encoded Image")
        encoded_file = st.file_uploader("Choose the image containing the hidden message", type=['png'], key="decode_uploader")

        if st.button("Decode Message", use_container_width=True, type="primary"):
            if encoded_file:
                try:
                    image = Image.open(encoded_file).convert("RGB")
                    
                    with st.status("Starting decoding process...", expanded=True) as status:
                        status.write("Extracting potential data from image pixels...")
                        extracted_data = extract_data_from_image(image)
                        time.sleep(1)

                        if not extracted_data:
                            st.error("No hidden message found or data is corrupted.")
                            status.update(label="Decoding Failed!", state="error")
                        else:
                            status.write("Data found! Decrypting with internal key...")
                            decrypted_message = decrypt_message(extracted_data, SECRET_KEY)
                            time.sleep(1)

                            if not decrypted_message:
                                st.error("Decryption failed. The data might be corrupted.")
                                status.update(label="Decoding Failed!", state="error")
                            else:
                                st.success("Message decoded successfully!")
                                st.text_area("Decoded Message:", decrypted_message, height=150)
                                status.update(label="Decoding complete!", state="complete")

                except Exception as e:
                    st.error(f"An unexpected error occurred during decoding: {e}")
            else:
                st.warning("Please provide an encoded image.")

if __name__ == '__main__':
    main()

