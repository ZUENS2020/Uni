import re
import math
import binascii
from collections import Counter

def calculate_entropy(data):
    """Calculates the Shannon entropy of a byte string."""
    if not data:
        return 0.0

    entropy = 0
    length = len(data)
    counts = Counter(data)

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy

def extract_strings(data, min_len=4):
    """Extracts printable ASCII strings from a byte string."""
    # Regex for printable ASCII characters, including space
    string_regex = f"[\x20-\x7E]{{{min_len},}}".encode('ascii')
    return [match.decode('ascii', errors='ignore') for match in re.findall(string_regex, data)]

def find_flags(data):
    """Finds common CTF flag formats in a byte string."""
    # Case-insensitive search for flag{...}, ctf{...}, key{...}
    flag_regex = rb'(flag|ctf|key)\{[^}]+\}'
    return [match.decode('utf-8', errors='ignore') for match in re.findall(flag_regex, data, re.IGNORECASE)]

def get_hex_preview(data, length=256):
    """Generates a hex and ASCII preview of the start and end of a byte string."""
    if len(data) <= length * 2:
        # If data is small, preview all of it
        head = data
        tail = b''
    else:
        head = data[:length]
        tail = data[-length:]

    def format_block(block, offset_start=0):
        lines = []
        for i in range(0, len(block), 16):
            chunk = block[i:i+16]
            hex_part = binascii.hexlify(chunk, ' ').decode('ascii')
            hex_part = hex_part.ljust(16 * 3 - 1)

            # Replace non-printable chars with '.'
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

            lines.append(f"0x{offset_start + i:08x}: {hex_part}  |{ascii_part}|")
        return "\n".join(lines)

    preview = {
        "head": format_block(head, 0),
        "tail": None
    }
    if tail:
        tail_offset = len(data) - len(tail)
        preview["tail"] = format_block(tail, tail_offset)

    return preview
