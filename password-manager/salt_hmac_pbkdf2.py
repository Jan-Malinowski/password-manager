import os
import hashlib

class Modol_Krypto:
    def __init__(self):
        self.block_size=64 # dlugosc bloku wejsciowego funkcji hashujacej
        self.hash_len=32 # dlugosc wyjscia funkcji hashujacej
    def generate_salt(self, leng: int=16) -> bytes:
        # leng - dlugosc wyjscia w bajtach - obecny standard min 16 bajtow
        return os.urandom(leng)

    def hmac_sha_256(self, key: bytes, message: bytes) -> bytes:
        if len(key)>self.block_size:
            key=hashlib.sha256(key).digest()
        if len(key)<self.block_size:
            key=key.ljust(self.block_size, b'\x00')

        i_key_pad=bytes((x ^ 0x36) for x in key)
        o_key_pad=bytes((x ^ 0x5c) for x in key)

        inner_hash=hashlib.sha256(i_key_pad+message).digest()
        return hashlib.sha256(o_key_pad+inner_hash).digest()

    def pbkdf2_hmac_sha_256(self, password: bytes, salt: bytes, iterations: int=600000, dklen: int=32) -> bytes:
        #dklen - dlugosc klucza wyjsciowego w bajtach - 32 bajty bo potrzebne do AES-256
        #iterations - obecnie zalecane min 600 000 przez OWASP
        blocks=(dklen-1)//self.hash_len + 1

        dk=b''
        for i in range(1,blocks+1):
            u=self.hmac_sha_256(password, salt+i.to_bytes(4,'big'))
            t=u
            for j in range(1,iterations):
                u=self.hmac_sha_256(password,u)
                t=bytes(a ^ b for a,b in zip(t,u))

            dk+=t
        return dk[:dklen]
