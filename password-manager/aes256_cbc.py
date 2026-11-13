from AES import AES256CORE

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size) # obliczanie ile bajtow brakuje do pelnego bloku
    data += bytes([pad_len] * pad_len)
    return data

def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1] # pobranie wartosci paddingu

    if pad_len<1 or pad_len>16:
        print("Error: Bledna dlugosc padingu")
        exit(0)

    return data[:-pad_len]

def xor(a: bytes, b:bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class AES256CBC:
    def __init__(self, key: bytes, iv: bytes):
        if len(iv) != 16:
            print("Error: zla dlugosc wektora inicjalizacji")
            exit(0)

        self.aes_core = AES256CORE(key)
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        padded_plaintext = pad_pkcs7(plaintext)
        ciphertext = b""
        prev_block = self.iv

        for i in range(0, len(padded_plaintext), 16):
            cur_block = padded_plaintext[i:i+16] # branie blokow 16 bajtowych
            xor_block = xor(cur_block, prev_block)
            encrypted_block = self.aes_core.encrypt_block(xor_block)
            ciphertext += encrypted_block
            prev_block = encrypted_block

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        padded_plaintext = b""
        prev_block = self.iv

        for i in range(0, len(ciphertext), 16):
            cur_block = ciphertext[i:i+16]
            decrypted_block = self.aes_core.decrypt_block(cur_block)
            padded_plaintext += xor(decrypted_block, prev_block)
            prev_block = cur_block

        return unpad_pkcs7(padded_plaintext)