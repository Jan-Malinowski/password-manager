from salt_hmac_pbkdf2 import Modol_Krypto

def test_hmac():
    print("Testy funkcji HMAC-SHA-256:")
    krypto=Modol_Krypto()
    key1=b'\x0b' * 20
    msg1="Hi There".encode("utf-8")
    result1="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

    if krypto.hmac_sha_256(key1,msg1).hex()==result1:
        print("Test 1 - OK")
    else:
        print("Test 1 - FAILED")

    key2="Jefe".encode("utf-8")
    msg2="what do ya want for nothing?".encode("utf-8")
    result2="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    if krypto.hmac_sha_256(key2,msg2).hex()==result2:
        print("Test 2 - OK")
    else:
        print("Test 2 - FAILED")

    key3=b'\xaa' * 20
    msg3=b'\xdd' * 50
    result3="773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"

    if krypto.hmac_sha_256(key3,msg3).hex()==result3:
        print("Test 3 - OK")
    else:
        print("Test 3 - FAILED")

    key4=bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819")
    msg4=b'\xcd' * 50
    result4="82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"

    if krypto.hmac_sha_256(key4,msg4).hex()==result4:
        print("Test 4 - OK")
    else:
        print("Test 4 - FAILED")

    key5=b'\xaa' * 131
    msg5="Test Using Larger Than Block-Size Key - Hash Key First".encode("utf-8")
    result5="60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"

    if krypto.hmac_sha_256(key5,msg5).hex()==result5:
        print("Test 5 - OK")
    else:
        print("Test 5 - FAILED")

    key6=b'\xaa' * 131
    msg6="This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".encode("utf-8")
    result6="9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"

    if krypto.hmac_sha_256(key6,msg6).hex()==result6:
        print("Test 6 - OK")
    else:
        print("Test 6 - FAILED")

def test_pbkdf2():
    print("Testy funkcji PBKDF2-HMAC-SHA-256:")
    krypto=Modol_Krypto()
    pa1="password".encode("utf-8")
    salt1="salt".encode("utf-8")
    c1=1
    dklen1=32
    result1="120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"

    if krypto.pbkdf2_hmac_sha_256(pa1,salt1,c1,dklen1).hex()==result1:
        print("Test 1 - OK")
    else:
        print("Test 1 - FAILED")

    pa2="password".encode("utf-8")
    salt2="salt".encode("utf-8")
    c2=2
    dklen2=32
    result2="ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"

    if krypto.pbkdf2_hmac_sha_256(pa2,salt2,c2,dklen2).hex()==result2:
        print("Test 2 - OK")
    else:
        print("Test 2 - FAILED")

    pa3="password".encode("utf-8")
    salt3="salt".encode("utf-8")
    c3=4096
    dklen3=32
    result3="c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"

    if krypto.pbkdf2_hmac_sha_256(pa3,salt3,c3,dklen3).hex()==result3:
        print("Test 3 - OK")
    else:
        print("Test 3 - FAILED")

    pa4="passwordPASSWORDpassword".encode("utf-8")
    salt4="saltSALTsaltSALTsaltSALTsaltSALTsalt".encode("utf-8")
    c4=4096
    dklen4=40
    result4="348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"

    if krypto.pbkdf2_hmac_sha_256(pa4,salt4,c4,dklen4).hex()==result4:
        print("Test 4 - OK")
    else:
        print("Test 4 - FAILED")

    pa5="pass\0word".encode("utf-8")
    salt5="sa\0lt".encode("utf-8")
    c5=4096
    dklen5=16
    result5="89b69d0516f829893c696226650a8687"

    if krypto.pbkdf2_hmac_sha_256(pa5,salt5,c5,dklen5).hex()==result5:
        print("Test 5 - OK")
    else:
        print("Test 5 - FAILED")

test_hmac()
test_pbkdf2()