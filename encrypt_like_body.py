# import sys, os
# sys.path.insert(0, os.path.join(os.path.dirname(__file__), "proto"))

# import like_pb2
# LikeProfileReq = like_pb2.like  # adjust if the class is _like
import base64
import binascii
from Crypto.Cipher import AES
from ff_proto import like_pb2
LikeProfileReq = like_pb2.like

# --- Garena API Encryption Constants ---
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

def pad(text: bytes) -> bytes:
    """
    Pads the data to be a multiple of AES block size (16 bytes).
    PKCS7 padding.
    """
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt data using AES-CBC.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext)
    return cipher.encrypt(padded)

def create_like_payload(uid: int, region: str) -> bytes:
    """
    Build and encrypt the protobuf payload for /LikeProfile request.
    Returns raw bytes ready to send.
    """
    # --- Step 1: Create protobuf message ---
    message = LikeProfileReq()
    message.uid = int(uid)
    message.region = region
    protobuf_bytes = message.SerializeToString()

    # --- Step 2: Encrypt using AES-CBC ---
    encrypted_bytes = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, protobuf_bytes)

    # --- Return raw bytes (ready for requests.post(data=...)) ---
    return encrypted_bytes

# --- Example usage / hardcoded test ---
if __name__ == "__main__":
    uid_to_like = 1002810438  # Hardcoded UID
    region = "IND"             # Hardcoded region

    payload = create_like_payload(uid_to_like, region)
    print("--- /LikeProfile Payload ---")
    print("Raw bytes:", payload)
    print("Hex string:", binascii.hexlify(payload).upper().decode())
