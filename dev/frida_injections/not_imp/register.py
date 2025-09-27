#!/usr/bin/env python3
import asyncio
import base64
import json
import sys
from typing import Tuple

import httpx
from Crypto.Cipher import AES
from google.protobuf import json_format, message

# Replace with actual generated proto modules
from proto import FreeFire_pb2        # used for token->login if needed (optional)
from proto.PlatformRegisterReq_pb2 import PlatformRegisterReq, EAuth_ClientUsingVersion

# AES key/iv (from your script)
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB50"

# ---------- crypto helpers ----------
def pad(b: bytes) -> bytes:
    l = AES.block_size - (len(b) % AES.block_size)
    return b + bytes([l])*l

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

# ---------- OAuth token grab ----------
async def get_access_token(uid: str, password: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id":"100067"
    }
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(url, data=payload, headers=headers)
        r.raise_for_status()
        j = r.json()
        return j.get("access_token"), j.get("open_id")

# ---------- MajorRegister builder + sender ----------
async def major_register_with_guest(uid: str, password: str, nickname: str, region: str = "IND"):
    # 1) get access_token & open_id
    access_token, open_id = await get_access_token(uid, password)
    if not access_token or not open_id:
        raise RuntimeError("failed to get access_token/open_id")

    # 2) build PlatformRegisterReq protobuf
    req = PlatformRegisterReq()
    req.nickname = nickname
    req.access_token = access_token
    req.open_id = open_id
    # req.region = region
    req.avatar_id = 102000007          # use your value or choose
    req.platform_type = 4              # main_active_platform = 4 (guest)
    req.platform_sdk_id = 1            # <-- important, from your decode
    # req.source = 0                     # if unknown, 0 (DownloadType_NONE). Adjust if needed.
    # req.editor_register_key = ""
    req.newbie_choice = 1              # NewbieChoice_NEW_PLAYER (adjust as you want)
    # platform_register_info left empty for now (b'')
    req.platform_register_info = b"RU\006T\001\004\000\010V\001\005\t\004\005\003\002\005\005\001\001\007\013\003PUQ\006\006URP\t"
    req.language = "en"
    req.using_version = EAuth_ClientUsingVersion.ClientUsingVersion_NORMAL
    req.is_newbie_choice = False

    # 3) serialize and encrypt
    plaintext = req.SerializeToString()
    encrypted = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, plaintext)

    # debug: print plaintext and payload hex (only if safe)
    print("--- plaintext proto (debug) ---")
    print(req)  # human readable
    print(f"plaintext len: {len(plaintext)} bytes")
    print("--- encrypted payload hex (first 200 chars) ---")
    print(encrypted.hex()[:400])

    # 4) send to MajorRegister
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
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(url, data=encrypted, headers=headers)
        print(f"Status: {r.status_code}")
        # server often returns text errors; try to print decoded text
        try:
            print("Response text:", r.text)
        except Exception:
            print("Response raw:", r.content)

# ---------- CLI ----------
async def main():
    if len(sys.argv) < 4:
        print("Usage: python major_register_auto.py <uid> <password> <nickname> [region]")
        return
    uid = sys.argv[1]
    password = sys.argv[2]
    nickname = sys.argv[3]
    region = sys.argv[4] if len(sys.argv) > 4 else "IND"
    await major_register_with_guest(uid, password, nickname, region)

if __name__ == "__main__":
    asyncio.run(main())
