import base64
from Crypto.Cipher import AES
import binascii
import sys

# --- Garena API Encryption Constants and Helpers ---

# These are the same constants used by the game client
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

def pad(text: bytes) -> bytes:
    """Pads the data to be a multiple of the AES block size."""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypts data using AES in CBC mode."""
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    ciphertext = aes.encrypt(padded_plaintext)
    return ciphertext

# --- Protobuf Encoding Logic ---

def encode_varint(number: int) -> bytes:
    """Encodes a 64-bit integer into a Protobuf Varint byte string."""
    result = b''
    while number > 127:
        result += bytes([(number & 0x7F) | 0x80])
        number >>= 7
    result += bytes([number])
    return result

def create_protobuf_payload(uid: int) -> bytes:
    """
    Creates the raw protobuf message for the LikeProfile request.
    
    The message contains a single field:
    uint64 uid = 3;
    
    The protobuf tag for Field 3 with a varint wire type is 0x18.
    """
    tag = 0x18  # (3 << 3) | 0
    uid_varint = encode_varint(uid)
    return bytes([tag]) + uid_varint

# --- Main Script ---

def main():
    print("--- Free Fire 'Like Profile' Request Body Generator ---")
    
    # Get UID from user input
    try:
        uid_input = input("Enter the UID you want to 'like': ")
        uid = int(uid_input)
    except ValueError:
        print("Invalid input. Please enter a valid integer UID.")
        sys.exit(1)
        
    print(f"\nGenerating request body for UID: {uid}...")
    
    # Step 1: Create the protobuf payload
    protobuf_payload = create_protobuf_payload(uid)
    print(f"1. Protobuf Payload (raw bytes): {protobuf_payload.hex().upper()}")
    
    # Step 2: Encrypt the payload
    encrypted_body = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, protobuf_payload)
    
    # Step 3: Convert the encrypted binary data to a hexadecimal string
    hex_body = binascii.hexlify(encrypted_body).upper()
    
    print(f"2. AES Encrypted Body (hex):     {hex_body.decode()}")

if __name__ == "__main__":
    main()
