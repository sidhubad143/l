import httpx
import asyncio
import binascii
import json
import os
import time
from get_jwt import create_jwt
from encrypt_like_body import create_like_payload  # protobuf + AES encryptor
from guests_manager.count_guest import count

# Paths
guests_file = "guests_manager/guests_converted.json"
usage_dir = "usage_history"
usage_file = os.path.join(usage_dir, "guest_usage_by_target.json")

# Ensure dirs
os.makedirs(usage_dir, exist_ok=True)

# Load usage file (per-target permanent mapping)
if os.path.exists(usage_file):
    with open(usage_file, "r") as f:
        usage_by_target = json.load(f)
else:
    usage_by_target = {}

# Helpers for per-target permanent skip
def ensure_target(target_uid: str):
    if target_uid not in usage_by_target:
        usage_by_target[target_uid] = {"used_guests": {}, "total_likes": 0}

def guest_used_for_target(target_uid: str, guest_uid: str) -> bool:
    # Permanent rule: if present in used_guests, skip forever for this target
    ensure_target(target_uid)
    return guest_uid in usage_by_target[target_uid]["used_guests"]

def mark_used(target_uid: str, guest_uid: str, ts_ms: int):
    ensure_target(target_uid)
    usage_by_target[target_uid]["used_guests"][guest_uid] = ts_ms  # timestamp for audit only
    usage_by_target[target_uid]["total_likes"] = len(usage_by_target[target_uid]["used_guests"])

def save_usage():
    with open(usage_file, "w") as f:
        json.dump(usage_by_target, f, indent=2)

# Inputs
uid_to_like = input("Enter UID to like: ").strip()
server_name_in = input("Enter server name (e.g., IND, BR, US, SAC, NA): ").strip().upper()

guest_count = count()
print(f"\n{guest_count} guest accounts found in '{guests_file}'")
print("\nFree Fire allows 1000 guest accounts to like a single profile within 24 hours")

requested_likes_in = input("How many likes you want to send? (recommended: 1000/day): ").strip()
requested_likes = int(requested_likes_in) if requested_likes_in else 1000

max_conc_in = input("How many like requests to send per second? (eg. 20): ").strip()
MAX_CONCURRENT = int(max_conc_in) if max_conc_in else 20
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

# Determine Base URL based on Server Input
def get_base_url(server_name: str) -> str:
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com"
    else:
        # Default/other regions based on the original server logic
        return "https://clientbp.ggblueshark.com"

# Resolve the base URL for the target server
BASE_URL = get_base_url(server_name_in)
# --------------------------------------------------

# Async worker
async def like_with_guest(guest: dict, target_uid: str) -> bool:
    guest_uid = str(guest["uid"])
    guest_pass = guest["password"]
    now_ms = int(time.time() * 1000)

    # Permanent skip check
    if guest_used_for_target(target_uid, guest_uid):
        print(f"[{guest_uid}] Permanently used for target {target_uid}, skipping...")
        return False

    async with semaphore:
        try:
            # Acquire JWT/region
            jwt, region, server_url_from_jwt = await create_jwt(guest_uid, guest_pass)

            # Build payload
            payload = create_like_payload(target_uid, region)
            if isinstance(payload, str):
                payload = binascii.unhexlify(payload)

            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UP1A.231005.007)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/octet-stream",
                "Expect": "1000-continue",
                "Authorization": f"Bearer {jwt}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB50",
            }

            async with httpx.AsyncClient() as client:
                # UPDATED ENDPOINT URL
                url = f"{BASE_URL}/LikeProfile"
                response = await client.post(url, data=payload, headers=headers, timeout=30)
                response.raise_for_status()

            print(f"[{guest_uid}] Like sent to {target_uid}! Status: {response.status_code}")
            # Permanently mark this guest as used for this target
            mark_used(target_uid, guest_uid, now_ms)
            return True

        except httpx.HTTPStatusError as err:
            body = err.response.text if err.response is not None else ""
            print(f"[{guest_uid}] HTTP error: {err}, Response: {body}")
        except httpx.RequestError as err:
            print(f"[{guest_uid}] Request exception: {err}")
        except Exception as e:
            print(f"[{guest_uid}] Unexpected error: {e}")

    return False

# Main
async def main():
    ensure_target(uid_to_like)

    # Load guest list
    with open(guests_file, "r") as f:
        guests = json.load(f)

    # Only consider guests that have never liked this target
    available_guests = [g for g in guests if not guest_used_for_target(uid_to_like, str(g["uid"]))]

    if not available_guests:
        print(f"No available guests left for target {uid_to_like} under permanent-skip policy.")
        save_usage()
        return

    likes_planned = min(max(0, requested_likes), len(available_guests))
    print(f"Planning to send {likes_planned} likes to {uid_to_like} using unused guests for this target.")

    tasks = []
    for g in available_guests[:likes_planned]:
        tasks.append(like_with_guest(g, uid_to_like))

    results = await asyncio.gather(*tasks)
    save_usage()

    success = sum(1 for r in results if r)
    print(f"Completed. Success: {success}/{likes_planned}. Total used guests for {uid_to_like}: {usage_by_target[uid_to_like]['total_likes']}")

if __name__ == "__main__":
    asyncio.run(main())
