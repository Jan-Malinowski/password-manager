from aes256_cbc import AES256CBC, pad_pkcs7, unpad_pkcs7 

def test_padding():
    print("Testy paddingu PKCS7:")
    
    data1 = b"TEST"
    result1 = b"TEST" + b"\x0c" * 12
    if pad_pkcs7(data1) == result1:
        print("Test 1 - OK")
    else:
        print("Test 1 - FAILED")

    data2 = b"1234567890123456"
    result2 = b"1234567890123456" + b"\x10" * 16
    if pad_pkcs7(data2) == result2:
        print("Test 2 - OK")
    else:
        print("Test 2 - FAILED")

    if unpad_pkcs7(result1) == data1:
        print("Test 3 - OK")
    else:
        print("Test 3 - FAILED")

    if unpad_pkcs7(result2) == data2:
        print("Test 4 - OK")
    else:
        print("Test 4 - FAILED")


def test_aes_cbc():
    print("\nTesty funkcji AES-256-CBC:")
    
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = AES256CBC(key, iv)

    msg1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_block_1 = "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    
    enc1 = cipher.encrypt(msg1)
    if enc1[:16].hex() == expected_block_1:
        print("Test 1 - OK")
    else:
        print("Test 1 - FAILED")

    msg2 = "Short".encode("utf-8")
    enc2 = cipher.encrypt(msg2)
    dec2 = cipher.decrypt(enc2)
    if dec2 == msg2:
        print("Test 2 - OK")
    else:
        print("Test 2 - FAILED")

    msg3 = b""
    enc3 = cipher.encrypt(msg3)
    dec3 = cipher.decrypt(enc3)
    if dec3 == msg3:
        print("Test 3 - OK")
    else:
        print("Test 3 - FAILED")

    msg4 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.".encode("utf-8")
    enc4 = cipher.encrypt(msg4)
    dec4 = cipher.decrypt(enc4)
    if dec4 == msg4:
        print("Test 4 - OK")
    else:
        print("Test 4 - FAILED")

    key5 = b'\xaa' * 32
    iv5 = b'\xbb' * 16 
    cipher5 = AES256CBC(key5, iv5)
    
    msg5 = "Test klucza numer 2".encode("utf-8")
    enc5 = cipher5.encrypt(msg5)
    dec5 = cipher5.decrypt(enc5)
    if dec5 == msg5:
        print("Test 5 - OK")
    else:
        print("Test 5 - FAILED")

test_padding()
test_aes_cbc()