import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from contextlib import suppress
import zlib
import struct
import json
import yara
import pefile


RULE_SOURCE = """rule MonsterV2Config
{
    meta:
        author = "doomedraven,YungBinary"
    strings:
        $chunk_1 = {
            41 B8 ?? ?? ?? ??
            48 8D 15 ?? ?? ?? ??
            48 8B CB
            E8 ?? ?? ?? ??
            48 8D 83 ?? ?? ?? ??
            48 89 44 24 ??
            48 89 6C 24 ??
            4C 8B C7
            48 8D 54 24 ??
            48 8B CE
            E8 ?? ?? ?? ??
        }
    condition:
        $chunk_1
}"""


def derive_chacha_key_nonce_blake2b(seed: bytes):  # -> tuple[bytes, bytes]:
    """
    Derives a 32-byte ChaCha20 key and a 24-byte ChaCha20 nonce
    using BLAKE2b from a given seed.
    """
    output_length = 56  # 32 bytes for key + 24 bytes for nonce
    h = hashlib.blake2b(digest_size=output_length)
    h.update(seed)
    derived_material = h.digest()
    chacha20_key = derived_material[0:32]
    chacha20_nonce = derived_material[32:56]
    return chacha20_key, chacha20_nonce


def yara_scan(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                return instance.offset

def extract_config(data: bytes) -> dict:
    config_dict = {}
    with suppress(Exception):
        pe = pefile.PE(data=data)
        offset = yara_scan(data, RULE_SOURCE)
        
        image_base = pe.OPTIONAL_HEADER.ImageBase
        disp_offset = data[offset + 9 : offset + 13]
        disp_offset = struct.unpack('i', disp_offset)[0]
        instruction_pointer_va = pe.get_rva_from_offset(offset + 13)
        config_offset_va = instruction_pointer_va + disp_offset
        config_offset = pe.get_offset_from_rva(config_offset_va)
        

        blake_seed = data[config_offset : config_offset + 32]
        chacha20_key, chacha20_nonce = derive_chacha_key_nonce_blake2b(blake_seed)
        cipher_len = int.from_bytes(data[config_offset + 32 : config_offset + 40], byteorder="big")
        cipher_text = data[config_offset + 40 : config_offset + 40 + cipher_len]

        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=chacha20_nonce)
        decrypted_zlib_data = cipher.decrypt(cipher_text)
        decompressed_data = zlib.decompress(decrypted_zlib_data)
        config_dict = json.loads(decompressed_data)
    
    return config_dict
        

if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
