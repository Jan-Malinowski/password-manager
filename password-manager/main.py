import os
import hashlib
import getpass

# wersja demo - funkcje do scalenia w tematyczne pliki python
from aes256_cbc import AES256CBC
from salt_hmac_pbkdf2 import Modol_Krypto
from encode_decode_base64 import encode_to_base64, decode_from_base64
from database_control import save_database, load_database, deserialize_data, serialize_data # do dokonczenia w ramach etapu 3

DB_FILE = "passwords.json"

def main():
    # wlaczenie aplikacji

    # inicjalizacja modulu krypto 
    crypto = Modol_Krypto()
    # wczytanie bazy hasel
    db_data = load_database(DB_FILE)

    #brak bazy lub klucza krypto - tworzenie od zera
    if not db_data or not db_data.get("crypto"):
        print("niw ykryto istniejacej bazy danych")
        while True:
            master_pass = getpass.getpass("Podaj haslo glowne: ")
            conf_pass = getpass.getpass("Potwierdz haslo glowne: ")
            if master_pass == conf_pass and len(master_pass)>0:
                break
            print("Haslo musza byc identyczne i o dlugosci wiekszej niz 0 znakow")

        salt = crypto.generate_salt(16)
        key_64 = crypto.pbkdf2_hmac_sha_256(master_pass.encode('utf-8'), salt)
        vault = []

    else:
        print("Wykryto baze danych")
        master_pass = getpass.getpass("Podaj haslo glowne: ")

        salt = decode_from_base64(db_data["crypto"]["salt"])
        key_64 = crypto.pbkdf2_hmac_sha_256(master_pass.encode('utf-8'), salt)

        b64_ciphertext = db_data.get("ciphertext", "")
        if b64_ciphertext:
            iv = decode_from_base64(db_data["crypto"]["iv"])
            ciphertext = decode_from_base64(b64_ciphertext)
            
            try:
                cipher = AES256CBC(key_64, iv)
                decrypted_bytes = cipher.decrypt(ciphertext)
                vault = deserialize_data(decrypted_bytes)
            except Exception as e:
                # blędy z unpad_pkcs7 - zle haslo i z hmac.compare_digest - uszkodzony/edytowany plik
                print(f"Error haslo nie poprawne lub plik uszkodzony")
                exit(1)
        else:
            vault = []

        print("Wszystko ok - odblokowanie dostepu")


    while True:
        print("\n\tMENU\n1. Dodaj nowe haslo\n2. Wyswietl hasla\n3. Wyjdz i zapisz\n")
        mode = input("Podaj {1/2/3}: ")

        if mode=="1":
            service = input("Podaj nazwe serwisu: ")
            login = input("Podaj login do serwisu: ")
            password = input("podaj haslo do serwisu: ")

            vault.append({"service": service, "login": login, "password": password})
            print("dodanie do RAM")


        elif mode=="2":
            print("\tTwoje Hasla")
            for id, cred in enumerate(vault, 1):
                print(f"[{id}] {cred['service']} | Login: {cred['login']} | Haslo: {cred['password']}")

        elif mode=="3":
            # generowanie nowego IV 
            new_iv = crypto.generate_salt(16)
            cipher = AES256CBC(key_64, new_iv)

            serialized_vault = serialize_data(vault)
            new_ciphertext = cipher.encrypt(serialized_vault)
            
            output_data = {
                "crypto": {
                    "salt": encode_to_base64(salt),
                    "iv": encode_to_base64(new_iv)
                },
                "ciphertext": encode_to_base64(new_ciphertext)
            }

            if save_database(DB_FILE, output_data):
                print("zapisano hasla poprawnie")
                exit(0)
            else:
                print("Blad przy zapisywaniu bazy")
                exit(1)

        else:
            print("Error: Podany number spoza zakresu")

if __name__ == "__main__":
    main()