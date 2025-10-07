import base64
from Crypto.Cipher import AES
from google.protobuf.message import DecodeError
import sys

from register_req_pb2 import PlatformRegisterReq

# Your AES key and IV (base64 decoded)
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted)

def hex_to_bytes(hex_str: str) -> bytes:
    # Remove spaces/newlines and convert
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    return bytes.fromhex(hex_str)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hex_string_file>")
        sys.exit(1)

    hex_file = sys.argv[1]
    with open(hex_file, "r") as f:
        hex_data = f.read()

    try:
        encrypted_bytes = hex_to_bytes(hex_data)
        decrypted_bytes = decrypt_aes_cbc(encrypted_bytes, MAIN_KEY, MAIN_IV)
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)

    try:
        msg = PlatformRegisterReq()
        msg.ParseFromString(decrypted_bytes)
    except DecodeError as e:
        print(f"Protobuf decoding failed: {e}")
        sys.exit(1)

    print("Decoded PlatformRegisterReq protobuf message:")
    print(msg)

if __name__ == "__main__":
    main()
