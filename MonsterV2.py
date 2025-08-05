import hashlib
from Crypto.Cipher import ChaCha20
import zlib
import struct
import json
import yara
import pefile


RULE_SOURCE = """rule MonsterV2Config
{
    meta:
        author = "YungBinary"
    strings:
        $chunk_1 = {
            41 B8 0E 04 00 00
            48 8D 15 ?? ?? ?? 00
            48 8B CB
            E8 ?? ?? ?? ??
            48 8D 83 0E 04 00 00
            48 89 44 24 30
            48 89 6C 24 70
            4C 8B C7
            48 8D 54 24 28
            48 8B CE
            E8 ?? ?? ?? ??
        }
    condition:
        $chunk_1
}"""


def bytes_to_words(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i+4], "little") for i in range(0, len(b), 4)]


def rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def chacha_generate_keystream_32_bytes(
    key_bytes: bytes,
    counter_nonce_bytes: bytes
) -> bytes:

    # Convert to 32-bit words (little-endian)
    key = bytes_to_words(key_bytes)
    counter_and_nonce = bytes_to_words(counter_nonce_bytes)
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    # Extract constants and inputs
    v1, v2, v3, v4 = constants
    v8, v70, v17, v78, v9, v15, v10, v76 = key
    v11, v12, v13, v14 = counter_and_nonce

    for _ in range(10):
        v18 = (v70 + v2) & 0xffffffff
        v19 = (v8 + v1) & 0xffffffff
        v20 = (v78 + v4) & 0xffffffff
        v21 = rotr32(v19 ^ v11, 16)
        v22 = (v21 + v9) & 0xffffffff
        v23 = rotr32(v20 ^ v14, 16)
        v24 = (v17 + v3) & 0xffffffff
        v25 = rotr32(v18 ^ v12, 16)
        v26 = (v25 + v15) & 0xffffffff
        v27 = rotr32(v24 ^ v13, 16)
        v28 = (v27 + v10) & 0xffffffff

        v29 = rotr32(v8 ^ v22, 20)
        v30 = (v29 + v19) & 0xffffffff
        v31 = rotr32(v30 ^ v21, 24)
        v32 = (v31 + v22) & 0xffffffff
        v33 = v29 ^ v32
        v34 = rotr32(v70 ^ v26, 20)
        v35 = (v34 + v18) & 0xffffffff
        v36 = rotr32(v33, 25)
        v37 = rotr32(v35 ^ v25, 24)
        v38 = (v37 + v26) & 0xffffffff
        v39 = rotr32(v34 ^ v38, 25)
        v40 = rotr32(v17 ^ v28, 20)
        v41 = (v39 + v30) & 0xffffffff
        v42 = (v40 + v24) & 0xffffffff
        v43 = rotr32(v42 ^ v27, 24)
        v73 = (v43 + v28) & 0xffffffff
        v44 = v73
        v45 = (v23 + v76) & 0xffffffff
        v46 = rotr32(v40 ^ v44, 25)
        v47 = (v46 + v35) & 0xffffffff
        v48 = rotr32(v78 ^ v45, 20)
        v49 = (v48 + v20) & 0xffffffff
        v50 = rotr32(v47 ^ v31, 16)
        v51 = rotr32(v49 ^ v23, 24)
        v52 = (v51 + v45) & 0xffffffff
        v53 = rotr32(v41 ^ v51, 16)
        v54 = rotr32(v48 ^ v52, 25)
        v74 = (v53 + v73) & 0xffffffff
        v55 = rotr32(v39 ^ v74, 20)
        v1 = (v55 + v41) & 0xffffffff
        v14 = rotr32(v1 ^ v53, 24)
        v75 = (v14 + v74) & 0xffffffff
        v70 = rotr32(v55 ^ v75, 25)
        v56 = (v50 + v52) & 0xffffffff
        v57 = (v36 + v49) & 0xffffffff
        v58 = rotr32(v46 ^ v56, 20)
        v2 = (v58 + v47) & 0xffffffff
        v59 = rotr32(v57 ^ v43, 16)
        v60 = (v59 + v38) & 0xffffffff
        v61 = (v54 + v42) & 0xffffffff
        v62 = rotr32(v61 ^ v37, 16)
        v63 = (v62 + v32) & 0xffffffff
        v11 = rotr32(v2 ^ v50, 24)
        v76 = (v11 + v56) & 0xffffffff
        v64 = rotr32(v58 ^ v76, 25)
        v17 = v64
        v10 = v75
        v65 = rotr32(v54 ^ v63, 20)
        v3 = (v65 + v61) & 0xffffffff
        v12 = rotr32(v3 ^ v62, 24)
        v9 = (v12 + v63) & 0xffffffff
        v66 = rotr32(v65 ^ v9, 25)
        v67 = rotr32(v36 ^ v60, 20)
        v4 = (v67 + v57) & 0xffffffff
        v78 = v66
        v13 = rotr32(v4 ^ v59, 24)
        v15 = (v13 + v60) & 0xffffffff
        v8 = rotr32(v67 ^ v15, 25)

    # Final output: 8 words → 32 bytes
    out_words = [v1, v2, v3, v4, v11, v12, v13, v14]
    out_bytes = b''.join(word.to_bytes(4, 'little') for word in out_words)
    return out_bytes


def mask32(x):
    return x & 0xFFFFFFFF


def add32(x, y):
    return mask32(x + y)


def left_rotate(x, n):
    return mask32(x << n) | (x >> (32 - n))


def quarter_round(block, a, b, c, d):
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 16)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 12)
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 8)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 7)


def chacha20_permute(block):
    for doubleround in range(10):
        quarter_round(block, 0, 4, 8, 12)
        quarter_round(block, 1, 5, 9, 13)
        quarter_round(block, 2, 6, 10, 14)
        quarter_round(block, 3, 7, 11, 15)
        quarter_round(block, 0, 5, 10, 15)
        quarter_round(block, 1, 6, 11, 12)
        quarter_round(block, 2, 7, 8, 13)
        quarter_round(block, 3, 4, 9, 14)


def words_from_bytes(b):
    assert len(b) % 4 == 0
    return [int.from_bytes(b[4 * i : 4 * i + 4], "little") for i in range(len(b) // 4)]


def bytes_from_words(w):
    return b"".join(word.to_bytes(4, "little") for word in w)


def chacha20_block(key, nonce, blocknum):
    constant_words = words_from_bytes(b"expand 32-byte k")
    key_words = words_from_bytes(key)
    nonce_words = words_from_bytes(nonce)

    original_block = [
        constant_words[0],  constant_words[1],  constant_words[2],  constant_words[3],
        key_words[0],       key_words[1],       key_words[2],       key_words[3],
        key_words[4],       key_words[5],       key_words[6],       key_words[7],
        mask32(blocknum),   nonce_words[0],     nonce_words[1],     nonce_words[2],
    ]

    permuted_block = list(original_block)
    chacha20_permute(permuted_block)
    for i in range(len(permuted_block)):
        permuted_block[i] = add32(permuted_block[i], original_block[i])
    return bytes_from_words(permuted_block)


def chacha20_stream(key, nonce, length, blocknum):
    output = bytearray()
    while length > 0:
        block = chacha20_block(key, nonce, blocknum)
        take = min(length, len(block))
        output.extend(block[:take])
        length -= take
        blocknum += 1
    return output


def chacha20_xor(message, key, nonce, counter):
    message_len = len(message)
    key_stream = chacha20_stream(key, nonce, message_len, counter)

    xor_key = bytearray()
    for i in range(message_len):
        xor_key.append(message[i] ^ key_stream[i])

    return xor_key


def yara_scan(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                return instance.offset

def extract_config(data: bytes) -> str:
    pe = pefile.PE(data=data)
    offset = yara_scan(data, RULE_SOURCE)
    if not offset:
        print("dfsgfgfd")
        return
    
    image_base = pe.OPTIONAL_HEADER.ImageBase
    disp_offset = data[offset + 9 : offset + 13]
    disp_offset = struct.unpack('i', disp_offset)[0]
    instruction_pointer_va = pe.get_rva_from_offset(offset + 13)
    config_offset_va = instruction_pointer_va + disp_offset
    config_offset = pe.get_offset_from_rva(config_offset_va)
    
    blake_key = data[config_offset : config_offset + 32]
    cipher_len = int.from_bytes(data[config_offset + 32 : config_offset + 40], byteorder="big")
    cipher_text = data[config_offset + 40 : config_offset + 40 + cipher_len]
    
    h = hashlib.blake2b(digest_size=56)
    h.update(blake_key)
    hash_digest = h.digest()

    key = hash_digest[:32]
    counter_and_nonce = hash_digest[32:48]
    chacha_nonce = hash_digest[-8:]
    keystream = chacha_generate_keystream_32_bytes(key, counter_and_nonce)

    nonce = b'\x00\x00\x00\x00' + chacha_nonce
    counter = 0x1

    compressed_data = chacha20_xor(cipher_text, keystream, nonce, counter)
    config_json = zlib.decompress(compressed_data)
    return json.loads(config_json)
        

if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))