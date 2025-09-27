# freefire-like-and-guest-api
## Project tree
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
