import httpx
import asyncio
import json
import base64
import sys
from typing import Tuple
from google.protobuf import json_format, message
from Crypto.Cipher import AES

# --- Protos ---
from proto import PlatformRegisterReq_pb2

# --- Global constants ---
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = ["IND", "BR", "SG", "RU", "ID", "TW", "US", "VN", "TH", "ME", "PK", "CIS"]

# --- Helper functions ---
async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    msg_instance = message_type()
    msg_instance.ParseFromString(encoded_data)
    return msg_instance

# --- Main function for register ---
async def major_register(
    nickname: str,
    access_token: str,
    open_id: str,
    region: str,
    avatar_id: int = 102000007,
    platform_type: int = 1,
    platform_sdk_id: int = 4,
    source: int = 0,
    editor_register_key: str = "",
    newbie_choice: int = 0,
    platform_register_info: bytes = b'RU\006T\001\004\000\010V\001\005\t\004\005\003\002\005\005\001\001\007\013\003PUQ\006\006URP\t',
    language: str = "en",
    using_version: int = 0,
    is_newbie_choice: bool = False
):
    # Build request as dict to match your proto
    req_dict = {
        "nickname": nickname,
        "access_token": access_token,
        "open_id": open_id,
        "region": region,
        "avatar_id": avatar_id,
        "platform_type": platform_type,
        "platform_sdk_id": platform_sdk_id,
        "source": source,
        "editor_register_key": editor_register_key,
        "newbie_choice": newbie_choice,
        "platform_register_info": base64.b64encode(platform_register_info).decode(),
        "language": language,
        "using_version": using_version,
        "is_newbie_choice": is_newbie_choice
    }

    # Serialize & encrypt
    encoded_result = await json_to_proto(json.dumps(req_dict), PlatformRegisterReq_pb2.PlatformRegisterReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    # Send request
    url = "https://loginbp.ggblueshark.com/MajorRegister"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(url, data=payload, headers=headers)
        return r.status_code, r.content

# --- Example runner ---
async def main():
    nickname = "Apex9P3?9_5"
    access_token = "c25c2352eb34549e6db72425298ce70a641c16b88672d592626b923922c2e082"
    open_id =  "c98ce53ae5f99e8e6957afb275c1660c"
    region = "IND"

    if region not in SUPPORTED_REGIONS:
       print("Unsupported region.")
       sys.exit(1)

    status, content = await major_register(nickname, access_token, open_id, region)
    print(f"Status: {status}")
    print(f"Raw response: {content}")

if __name__ == "__main__":
    asyncio.run(main())
