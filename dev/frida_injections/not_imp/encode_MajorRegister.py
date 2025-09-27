import base64
from Crypto.Cipher import AES
from google.protobuf.message import EncodeError
from PlatformRegisterReq_pb2 import PlatformRegisterReq, EAccount_DownloadType, EAccount_NewbieChoice, EAuth_ClientUsingVersion

# Constants — replace with your actual keys & IV
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data))

def create_message(nickname, access_token, open_id):
    msg = PlatformRegisterReq()
    msg.nickname = nickname
    msg.access_token = access_token
    msg.open_id = open_id
    msg.region = "IND"  # example, change if needed
    msg.avatar_id = 102000007
    msg.platform_type = 4
    msg.platform_sdk_id = 1
    msg.source = EAccount_DownloadType.DownloadType_NONE
    msg.editor_register_key = ""
    msg.newbie_choice = EAccount_NewbieChoice.NewbieChoice_NEW_PLAYER
    msg.platform_register_info = b""
    msg.language = "en"
    msg.using_version = EAuth_ClientUsingVersion.ClientUsingVersion_NORMAL
    msg.is_newbie_choice = True
    return msg

def encode_and_encrypt(nickname, access_token, open_id):
    msg = create_message(nickname, access_token, open_id)
    try:
        serialized = msg.SerializeToString()
    except EncodeError as e:
        print(f"Failed to serialize protobuf message: {e}")
        return None

    # Print serialized protobuf (pre-encryption) in hex for debugging
    print("Serialized protobuf bytes (hex):")
    print(" ".join(f"{b:02X}" for b in serialized))
    print()

    encrypted = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, serialized)
    return encrypted.hex()

if __name__ == "__main__":
    nickname = "Fun0?6v8"
    access_token = "35dd0f60ee109ab2d033fc7c6399437a5b7f525e4ba21b28854fb7fb45180d50"
    open_id = "be6f1578f15965255511793aba66ebb9"

    encrypted_hex = encode_and_encrypt(nickname, access_token, open_id)
    if encrypted_hex:
        print("Encrypted hex (no spaces):")
        print(encrypted_hex.upper() + '\n')
        print("Encrypted hex (with spaces):")
        raw_hex = " ".join(encrypted_hex[i:i+2] for i in range(0, len(encrypted_hex), 2)).upper()
        print(raw_hex.strip())
