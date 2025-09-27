# FreeFire Guest generator, Like & API Toolkit

Automates capturing **Free Fire guest credentials** via **Frida**, formats and manages them, obtains **JWTs**, and sends encrypted like requests to a target UID with **concurrency controls** and **one-like-per-guest-per-target guarantees**.

---

## Features
- Capture guest **uid/password/token** from the Android app via **Frida hooks** and persist on-device with de-duplication.
- **Auto-loop** guest creation by restarting after successful registration to mass-generate accounts.
- Convert captured guests into structured **JSONs**, skipping duplicates and invalid entries.
- Authenticate guests to obtain a **JWT** using **AES-CBC–wrapped protobuf requests**.
- Build protobuf **LikeProfile payloads**, **AES-CBC encrypt** them, and send **concurrent likes** with usage tracking.

---

## Repository structure
- **dev/frida_injections**: Frida scripts for capture and auto-restart flows.
- **ff_proto**: Protobufs used by authentication and like payload builders.
- **guests_manager**: Tools and data for formatting and storing captured guests.
- **Python clients**: JWT acquisition, like payload encryption, and like sender.
- **index.js**: Il2Cpp/Frida helpers used by injection scripts.

---

## Prerequisites
- **Android device** with **Frida server** or **Frida Gadget**, reachable via USB or TCP.
- **Python 3.10+** with `httpx`, `pycryptodome`, `protobuf` installed.
- **Protobuf modules compiled** and present under `ff_proto` (`FreeFire_pb2.py`, `like_pb2.py`).

### Install:
    pip install httpx pycryptodome protobuf
    or 
    pip install -r requirements.txt

---

## 👤 Guest account creation workflow
- Attach `capture_and_save_guest.js` while launching the game to hook SharedPreferences and relevant classes, collecting uid/password/token.
- The script reads an existing `guest_accounts.json` in the app’s external media directory, appends unique entries, and writes atomically.
- Optional: Load `restart_after_register.js` to detect registration completion and trigger a timed restart for continuous guest generation.

### Launch options:
- **Interactive**: `python3 dev/frida_injections/frida_manager.py` (choose USB/TCP and scripts).
- Then use image clicker to click on respective positions one after another and the script will work on its own save guest data in the apps permissible dir inside `Android/data/com.dts.freefiremax/`
- **Manual**: `frida -U -n Gadget -l dev/frida_injections/capture_and_save_guest.js -l dev/frida_injections/restart_after_register.js -l dev/frida_injections/index.js`.

### Notes:
- `frida_manager.py` validates connectivity, restarts sessions, and manages default script lists; adjust `PROCESS_NAME`/`DEFAULT_JS_SCRIPTS` as needed.

## Convert and deduplicate guests
- Run: `python3 guests_manager/save_guest.py` to merge new captures into repo JSONs.
- Outputs: `formatted_guests.json` map and `guests_converted.json` flat array used by automation.
- Behavior: skips duplicates, ignores `unknown_*` placeholders, preserves numbering, and reports counts.

---


## Builds encrypted Like payload
- **Function**: `create_like_payload(uid_to_like, region) -> bytes (application/octet-stream)`
- **Internals**: constructs `like_pb2.like`, serializes, applies PKCS7 padding, AES-CBC encrypts the serialized bytes with `MAIN_KEY` / `MAIN_IV`, and returns the encrypted payload ready for POST.

---

## ⚡Send likes (concurrent, safe)
- Run: `python3 send_like.py`, then provide target UID, desired like count, and max concurrency.
- **Behavior**:  
  - Loads guests from `guests_converted.json`  
  - Obtains JWT and region per guest (via the JWT flow) if not cached  
  - Builds an encrypted Like payload using `create_like_payload`  
  - Posts the encrypted payload to the LikeProfile endpoint with required headers and auth  
  - Retries transient errors and respects per-request backoff / RPS limits
- **Guarantee**: one-like-per-guest-per-target enforced via `usage_history/guest_usage_by_target.json`.
- Concurrency controls and RPS limiting are applied to reduce throttling and detect rate limits early.

---

## 🪛Configuration tips
- If using Gadget, keep `PROCESS_NAME="Gadget"`; otherwise set the app process name in `frida_manager.py`.
- Tune concurrency and RPS to avoid throttling and fit within daily per-target limits.
- Prefer the `server_url` returned by the JWT flow when endpoints are region-scoped.

---

## Data files
- `guests_manager/formatted_guests.json`: human-readable map of captured guests.
- `guests_manager/guests_converted.json`: automation-ready array used by the sender.
- `usage_history/guest_usage_by_target.json`: tracks which guest has liked which target to enforce one-like-per-guest-per-target.

---
## 🌲Project tree
```bash
freefire-like-and-guest-api
├── LICENSE
├── README.md
├── dev
│   ├── frida_injections
│   │   ├── capture_and_save_guest.js
│   │   ├── frida_manager.py
│   │   ├── index.js
│   │   ├── not_imp
│   │   │   ├── class.js
│   │   │   ├── class_new.js
│   │   │   ├── decode_MajorRegister.py
│   │   │   ├── decoder.py
│   │   │   ├── decoder_rw_pb.py
│   │   │   ├── decrypt_like_body.py
│   │   │   ├── dummy.py
│   │   │   ├── encode.py
│   │   │   ├── encode_MajorRegister.py
│   │   │   ├── find_blob.js
│   │   │   ├── frida_manger.py
│   │   │   ├── log_class.js
│   │   │   ├── main.py
│   │   │   ├── native_ssl_bypass.js
│   │   │   ├── nativelog.js
│   │   │   ├── nativelog_new.js
│   │   │   ├── platform_info_constructor.js
│   │   │   ├── protobufwalker.py
│   │   │   ├── rawhex.hex
│   │   │   ├── register.py
│   │   │   ├── req_body_likeprofile.py
│   │   │   └── requst_body.hex
│   │   └── restart_after_register.js
│   └── not_imp
│       ├── decoder.py
│       ├── like.py
│       ├── main.py
│       ├── proto_brute
│       │   ├── PlatformRegisterReq.proto
│       │   ├── PlatformRegisterReq_pb2.py
│       │   ├── PlatformRegisterReq_template.proto
│       │   ├── main.py
│       │   ├── proto_trials
│       │   │   ├── PlatformRegisterReq.proto
│       │   │   └── PlatformRegisterReq_pb2.py
│       │   └── rawhex.hex
│       └── rawhex.hex
├── encrypt_like_body.py
├── ff_proto
│   ├── AccountPersonalShow_pb2.py
│   ├── FreeFire_pb2.py
│   ├── PlatformRegisterReq.proto
│   ├── PlatformRegisterReq_pb2.py
│   ├── like_count_pb2.py
│   ├── like_pb2.py
│   └── main_pb2.py
├── get_jwt.py
├── guests_manager
│   ├── count_guest.py
│   ├── formatted_guests.json
│   ├── guests_converted.json
│   ├── rm_duplicates.py
│   ├── save_guest.py
│   └── unreg_guests
│       ├── formatted_guests.json.lock
│       └── guests_converted_unregisterd.json
├── send_like.py
└── usage_history

11 directories, 56 files
```

- Inside the `dev/not_imp` & `dev/frida_injections/not_imp/` there are my all works, the scripts, methods i used to create this repository. It's more than a diamond if you can understand what those things are for.
