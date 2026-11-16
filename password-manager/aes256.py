SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for id, val in enumerate(SBOX):
    INV_SBOX[val] = id

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]


def gf_mul(a: int, b: int) -> int:
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        highest_bit = a & 0x80
        a = (a << 1) & 0xFF

        if highest_bit:
            a ^= 0x1B

        b >>= 1

    return result


class AES256CORE:
    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError(f"Error: Klucz musi być typu bytes, otrzymano {type(key).__name__}")
        if len(key) != 32:
            raise ValueError(f"Error: Klucz AES-256 musi mieć 32 bajty, otrzymano {len(key)}")
        self.key = key
        self.round_keys = self._expand_key(self.key)

    @staticmethod
    def _rotate_word(word: bytes) -> bytes:
        return word[1:] + word[:1]

    @staticmethod
    def _sub_word(word: bytes) -> bytes:
        return bytes(SBOX[b] for b in word)

    def _expand_key(self, key: bytes) -> list[bytes]:
        words = [key[i:i + 4] for i in range(0, len(key), 4)]

        for i in range(8, 60):
            temp = words[i - 1]
            if i % 8 == 0:
                temp = self._sub_word(self._rotate_word(temp))
                temp = bytes([temp[0] ^ RCON[i // 8], *temp[1:]])
            elif i % 8 == 4:
                temp = self._sub_word(temp)

            words.append(bytes(a ^ b for a, b in zip(words[i - 8], temp)))

        return words

    @staticmethod
    def _add_round_key(state: list[list[int]], round_key: list[bytes]) -> list[list[int]]:
        return [
            [state[row][column] ^ round_key[column][row] for column in range(4)]
            for row in range(4)
        ]

    @staticmethod
    def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
        return [[SBOX[b] for b in row] for row in state]

    @staticmethod
    def _inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
        return [[INV_SBOX[b] for b in row] for row in state]

    @staticmethod
    def _shift_rows(state: list[list[int]]) -> list[list[int]]:
        return [state[0],
                state[1][1:] + state[1][:1],
                state[2][2:] + state[2][:2],
                state[3][3:] + state[3][:3]]

    @staticmethod
    def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
        return [state[0],
                state[1][-1:] + state[1][:-1],
                state[2][-2:] + state[2][:-2],
                state[3][-3:] + state[3][:-3]]

    @staticmethod
    def _mix_columns(state: list[list[int]]) -> list[list[int]]:
        result = [[0] * 4 for _ in range(4)]

        for column in range(4):
            a0 = state[0][column]
            a1 = state[1][column]
            a2 = state[2][column]
            a3 = state[3][column]

            result[0][column] = (
                gf_mul(0x02, a0) ^
                gf_mul(0x03, a1) ^
                a2 ^
                a3
            )

            result[1][column] = (
                a0 ^
                gf_mul(0x02, a1) ^
                gf_mul(0x03, a2) ^
                a3
            )

            result[2][column] = (
                a0 ^
                a1 ^
                gf_mul(0x02, a2) ^
                gf_mul(0x03, a3)
            )

            result[3][column] = (
                gf_mul(0x03, a0) ^
                a1 ^
                a2 ^
                gf_mul(0x02, a3)
            )

        return result


    @staticmethod
    def _inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
        result = [[0] * 4 for _ in range(4)]

        for column in range(4):
            a0 = state[0][column]
            a1 = state[1][column]
            a2 = state[2][column]
            a3 = state[3][column]

            result[0][column] = (
                gf_mul(0x0E, a0) ^
                gf_mul(0x0B, a1) ^
                gf_mul(0x0D, a2) ^
                gf_mul(0x09, a3)
            )

            result[1][column] = (
                gf_mul(0x09, a0) ^
                gf_mul(0x0E, a1) ^
                gf_mul(0x0B, a2) ^
                gf_mul(0x0D, a3)
            )

            result[2][column] = (
                gf_mul(0x0D, a0) ^
                gf_mul(0x09, a1) ^
                gf_mul(0x0E, a2) ^
                gf_mul(0x0B, a3)
            )

            result[3][column] = (
                gf_mul(0x0B, a0) ^
                gf_mul(0x0D, a1) ^
                gf_mul(0x09, a2) ^
                gf_mul(0x0E, a3)
            )

        return result

    def encrypt_block(self, block: bytes) -> bytes:
        if not isinstance(block, bytes):
            raise TypeError(f"Error: Blok musi być typu bytes, otrzymano {type(block).__name__}")
        if len(block) != 16:
            raise ValueError(f"Error: Blok AES musi mieć 16 bajtów, otrzymano {len(block)}")

        state = [[block[i + 4 * j] for j in range(4)] for i in range(4)]
        state = self._add_round_key(state, self.round_keys[0:4])

        for round in range(1, 14):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round * 4:(round + 1) * 4])

        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[56:60])
        return bytes(state[row][column] for column in range(4) for row in range(4))

    def decrypt_block(self, block: bytes) -> bytes:
        if not isinstance(block, bytes):
            raise TypeError(f"Error: Blok musi być typu bytes, otrzymano {type(block).__name__}")
        if len(block) != 16:
            raise ValueError(f"Error: Blok AES musi mieć 16 bajtów, otrzymano {len(block)}")
        state = [[block[i + 4 * j] for j in range(4)] for i in range(4)]
        state = self._add_round_key(state, self.round_keys[56:60])

        for round in range(13, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[round * 4:(round + 1) * 4])
            state = self._inv_mix_columns(state)

        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0:4])
        return bytes(state[row][column] for column in range(4) for row in range(4))