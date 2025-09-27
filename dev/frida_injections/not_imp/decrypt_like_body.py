import base64
import binascii
from Crypto.Cipher import AES
import sys

# IMPORTANT: This script requires 'like_pb2.py' to be in the same directory.
# If it's in a different location (e.g., app/proto), you'll need to update the import statement.
from like_pb2 import like as LikeProfileReq

# --- Garena API Encryption Constants and Helpers ---
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

def unpad(data: bytes) -> bytes:
    """Removes PKCS7 padding from the data."""
    padding_length = data[-1]
    return data[:-padding_length]

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypts AES-encrypted data and removes padding."""
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_data = aes.decrypt(ciphertext)
    return unpad(decrypted_padded_data)

# --- Main Script ---
def main():
    print("--- Free Fire 'Like Profile' Request Body Decoder ---")
    
    try:
        # Example hex string from the user's input
        hex_input = "72 C1 20 26 86 96 0C C6 93 B8 11 04 EB 01 99 40"
        ciphertext = binascii.unhexlify(hex_input.replace(" ", ""))
    except binascii.Error:
        print("Invalid hexadecimal input.")
        sys.exit(1)
    
    print("\nProcessing...")
    
    try:
        # Step 1: Decrypt the ciphertext to get the raw Protobuf message
        protobuf_payload = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, ciphertext)
        print(f"1. Decrypted Protobuf Payload (hex): {protobuf_payload.hex().upper()}")

        # Step 2: Parse the Protobuf message using the generated class
        request_message = LikeProfileReq()
        request_message.ParseFromString(protobuf_payload)

        # Step 3: Print the decoded fields
        print("\n--- Decoded Message ---")
        print(f"UID:    {request_message.uid}")
        print(f"Region: {request_message.region}")
    
    except Exception as e:
        print(f"An error occurred during decoding: {e}")
        
if __name__ == "__main__":
    main()
