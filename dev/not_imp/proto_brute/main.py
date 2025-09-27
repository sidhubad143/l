import itertools
import subprocess
import os
import sys
import importlib.util
from google.protobuf.message import DecodeError

# Constants
PROTO_TEMPLATE_PATH = "PlatformRegisterReq_template.proto"
PROTO_GENERATED_PATH = "PlatformRegisterReq.proto"
PB2_MODULE_NAME = "PlatformRegisterReq_pb2"
HEX_INPUT_FILE = "rawhex.hex"

# Field definitions to permute from 7 to 14 (field_name, type)
# Adjust these as per your original proto, only fields 7 to 14 here.
fields_to_permute = [
    ("platform_sdk_id", "uint32"),
    ("source", "EAccount_DownloadType"),
    ("editor_register_key", "string"),
    ("newbie_choice", "EAccount_NewbieChoice"),
    ("platform_register_info", "bytes"),
    ("language", "string"),
    ("using_version", "EAuth_ClientUsingVersion"),
    ("is_newbie_choice", "bool"),
]

# Fixed fields 1 to 6 as per confirmed order and types (won't change)
fixed_fields = [
    ('nickname', 'string', 1),
    ('access_token', 'string', 2),
    ('open_id', 'string', 3),
    ('region', 'string', 4),
    ('avatar_id', 'uint32', 5),
    ('platform_type', 'uint32', 6),
]

def generate_proto_file(field_order):
    """
    Generate the PlatformRegisterReq.proto file with given field order for fields 7 to 14.
    field_order is a list of (name, type)
    """
    with open(PROTO_TEMPLATE_PATH, "r") as f:
        template = f.read()

    # Build the new fields section for 7-14
    fields_proto = []
    for i, (name, ftype) in enumerate(field_order, start=7):
        fields_proto.append(f"    {ftype} {name} = {i};")

    # Insert the fields into the template (assume placeholder: /*FIELDS7-14*/ )
    proto_content = template.replace("/*FIELDS7-14*/", "\n".join(fields_proto))

    with open(PROTO_GENERATED_PATH, "w") as f:
        f.write(proto_content)

def compile_proto():
    """Compile the .proto to _pb2.py using protoc."""
    result = subprocess.run(["protoc", "--python_out=.", PROTO_GENERATED_PATH], capture_output=True)
    if result.returncode != 0:
        print("protoc compile failed:", result.stderr.decode())
        sys.exit(1)

def import_pb2_module():
    """Dynamically import the generated pb2 module."""
    spec = importlib.util.spec_from_file_location(PB2_MODULE_NAME, PB2_MODULE_NAME + ".py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_hex_data():
    with open(HEX_INPUT_FILE, "r") as f:
        hex_str = f.read().replace(" ", "").replace("\n", "")
    return bytes.fromhex(hex_str)

def try_decode(proto_module, data):
    msg = proto_module.PlatformRegisterReq()
    try:
        msg.ParseFromString(data)
        # If parsing succeeds and nickname or access_token present, consider success
        if msg.nickname or msg.access_token:
            print("Successfully decoded with this field order:")
            print(msg)
            return True
        return False
    except DecodeError:
        return False

def main():
    hex_data = load_hex_data()

    # Generate all permutations of fields 7 to 14
    for perm in itertools.permutations(fields_to_permute):
        # Generate proto with this perm
        generate_proto_file(perm)

        # Compile proto file
        compile_proto()

        # Import the compiled pb2 module
        proto_module = import_pb2_module()

        # Try decoding
        if try_decode(proto_module, hex_data):
            print("Field order found!")
            print("Order of fields 7 to 14:")
            for idx, (name, ftype) in enumerate(perm, start=7):
                print(f"  {idx}: {ftype} {name}")
            break
    else:
        print("No valid field order found.")

if __name__ == "__main__":
    main()
