# decode_raw_pb_safe.py
import sys
from google.protobuf.internal import decoder, wire_format

def decode_varint(buf, pos):
    return decoder._DecodeVarint(buf, pos)

def decode_length_delimited(buf, pos):
    size, pos = decode_varint(buf, pos)
    return buf[pos:pos+size], pos+size

def parse_protobuf(buf):
    pos = 0
    while pos < len(buf):
        try:
            key, pos = decode_varint(buf, pos)
        except IndexError:
            break

        field_number = key >> 3
        wire_type = key & 0x7

        if wire_type == wire_format.WIRETYPE_VARINT:
            value, pos = decode_varint(buf, pos)
        elif wire_type == wire_format.WIRETYPE_FIXED64:
            value = buf[pos:pos+8]
            pos += 8
        elif wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
            value, pos = decode_length_delimited(buf, pos)
        elif wire_type == wire_format.WIRETYPE_FIXED32:
            value = buf[pos:pos+4]
            pos += 4
        elif wire_type == wire_format.WIRETYPE_START_GROUP:
            print(f"Field {field_number} (start group) — skipping")
            continue
        elif wire_type == wire_format.WIRETYPE_END_GROUP:
            print(f"Field {field_number} (end group)")
            continue
        else:
            print(f"Unknown wire type {wire_type} at field {field_number}, skipping rest")
            break

        print(f"Field {field_number} (wire_type={wire_type}): {value}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} rawhex.hex")
        sys.exit(1)

    # Read hex file
    with open(sys.argv[1], "r") as f:
        hex_str = f.read().replace(" ", "").replace("\n", "")
    buf = bytes.fromhex(hex_str)

    parse_protobuf(buf)
