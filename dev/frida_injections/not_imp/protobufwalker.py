import sys

def read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise EOFError("Unexpected end of buffer while reading varint")
        b = buf[pos]
        pos += 1
        result |= ((b & 0x7F) << shift)
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def parse_protobuf(buf):
    pos = 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        field_number = key >> 3
        wire_type = key & 0x07

        print(f"\nField {field_number} (wire_type={wire_type}):", end=' ')

        if wire_type == 0:  # varint
            value, pos = read_varint(buf, pos)
            print(f"varint: {value}")

        elif wire_type == 1:  # 64-bit
            value = buf[pos:pos+8]
            pos += 8
            print(f"64-bit: {value.hex()}")

        elif wire_type == 2:  # length-delimited
            length, pos = read_varint(buf, pos)
            value = buf[pos:pos+length]
            pos += length
            hex_preview = value.hex()
            try:
                str_preview = value.decode('utf-8', errors='ignore')
            except:
                str_preview = ''
            print(f"len={length}, hex={hex_preview}")
            if str_preview.strip():
                print(f"   [string preview: {str_preview[:80]}]")

        elif wire_type == 5:  # 32-bit
            value = buf[pos:pos+4]
            pos += 4
            print(f"32-bit: {value.hex()}")

        elif wire_type in (3, 4):  # groups (deprecated)
            print("(group start/end) - skipping for now")

        else:
            print("Unknown wire type!")
            break

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hexfile>")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        hex_data = bytes.fromhex(f.read().strip())

    parse_protobuf(hex_data)

if __name__ == "__main__":
    main()
