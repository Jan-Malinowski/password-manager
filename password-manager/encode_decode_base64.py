# etap 3 projektu - zarzadzanie plikami i danymi
import base64

def encode_to_base64(bin_data: bytes) -> str:
    return base64.b64encode(bin_data).decode('utf-8')

def decode_from_base64(base64_str: str) -> bytes:
    return base64.b64decode(base64_str)
