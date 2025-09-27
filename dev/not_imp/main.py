import httpx
import asyncio
import binascii
import json
from get_jwt import create_jwt
from encrypt_like_body import create_like_payload  # Your protobuf + AES encryptor
from guests_manager.count_guest import count
# Hardcoded uid to like
uid_to_like = input("Enter UID to like: ")

# Path to your JSON file
guests_file = "guests_manager/guests_converted.json"
guest_count = count()
print(f"{guest_count} guest accounts found in '{guests_file}'")
print("Free Fire allows 100 guest accounts to like a single profile in within 24 hours")
use_guest = int(input("How many likes you want to send? (recommended:100/day): ").strip())
if use_guest == "":
   use_guest = 100
else:
   pass
# Limit concurrent requests
MAX_CONCURRENT = int(input("How many requests you want to send per second? (eg. 50): "))
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

# --- Async function to send like for a single guest ---
async def like_with_guest(guest):
    guest_uid = guest["uid"]
    guest_pass = guest["password"]

    async with semaphore:  # Limit concurrency
        try:
            # Get JWT and server info
            jwt, region, server_url = await create_jwt(guest_uid, guest_pass)

            # Prepare payload
            payload = create_like_payload(uid_to_like, region)
            if isinstance(payload, str):
                payload = binascii.unhexlify(payload)

            # Headers
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

            # Send the request
            async with httpx.AsyncClient() as client:
                response = await client.post("https://client.ind.freefiremobile.com/LikeProfile", data=payload, headers=headers)
                response.raise_for_status()
                print(f"[{guest_uid}] Like sent successfully! Status: {response.status_code}")
        except httpx.HTTPStatusError as err:
            print(f"[{guest_uid}] HTTP error: {err}, Response: {err.response.text}")
        except httpx.RequestError as err:
            print(f"[{guest_uid}] Request exception: {err}")
        except Exception as e:
            print(f"[{guest_uid}] Unexpected error: {e}")

# --- Main async loop to process all guests concurrently ---
async def main():
    # Load all guests from JSON
    with open(guests_file, "r") as f:
        guests = json.load(f)

    # Create tasks for all guests
    tasks = [

             like_with_guest(guest) for guest in guests



]

    # Run all tasks concurrently
    await asyncio.gather(*tasks)

# Run the async main
asyncio.run(main())
