import httpx
import asyncio
import binascii
from get_jwt import create_jwt
from encrypt_like_body import create_like_payload  # Your protobuf + AES encryptor

# --- Hardcoded credentials ---
guest_uid = "4103701466"
guest_pass = "81EA673E652E61BA3C70531693CAE417314E5D67563E2535EF30430296F24A4F"
uid_to_like = "1002810438"

# Global variables
jwt = None
region = None
server_url = None

# --- Async function to get credentials ---
async def get_creds():
    global jwt, region, server_url
    jwt, region, server_url = await create_jwt(guest_uid, guest_pass)

# --- Run the async function to populate globals ---
asyncio.run(get_creds())

# --- Prepare payload ---
payload = create_like_payload(uid_to_like, region)  # Returns raw bytes
# If your create_like_payload() returns hex string, convert it:
if isinstance(payload, str):
    payload = binascii.unhexlify(payload)

# --- Headers ---
headers = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 15; I2404 Build/AP3A.240905.015.A2_V000L1)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/octet-stream",
    'Expect': "100-continue",
    'Authorization': f"Bearer {jwt}",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50",
}

# --- Make the request ---
try:
    response = httpx.post("https://client.ind.freefiremobile.com/LikeProfile", data=payload, headers=headers)
    response.raise_for_status()
    print("Request successful!")
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)
except httpx.HTTPStatusError as err:
    print(f"HTTP error occurred: {err}")
    print(f"Response Body: {response.text}")
except httpx.RequestError as err:
    print(f"Request exception occurred: {err}")
