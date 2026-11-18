import os
import getpass

from aes256_cbc import AES256CBC
from modol_krypto import Modol_Krypto
from encode_decode_base64 import encode_to_base64, decode_from_base64
from database_control import save_database, load_database, deserialize_data, serialize_data

DB_FILE = "passwords.json"

def main():
    # wlaczenie aplikacji

    # inicjalizacja modulu krypto 
    crypto = Modol_Krypto()

    if not os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "w", encoding="utf-8") as f:
                f.write("{\n}")
        except OSError as e:
            print(f"Blad tworzenia pliku bazy danych: {e}")
            exit(1)
    # wczytanie bazy hasel
    db_data = load_database(DB_FILE)

    #brak bazy lub klucza krypto - tworzenie od zera
    if not db_data or not db_data.get("crypto"):
        print("nie wykryto istniejacej bazy danych")
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

            saved_mac=decode_from_base64(db_data["crypto"]["mac"])
            expected_mac=crypto.hmac_sha_256(key_64,iv + ciphertext)
            
            if not crypto.const_time_compare_hmac(saved_mac,expected_mac):
                print("Error haslo nie poprawne lub plik bazy byl modyfikowany")
                exit(1)
            
            try:
                cipher = AES256CBC(key_64, iv)
                decrypted_bytes = cipher.decrypt(ciphertext)
                vault = deserialize_data(decrypted_bytes)
            except Exception as e:
                print(f"Error blad podczas odszyfrowywania")
                exit(1)
        else:
            vault = []

        print("Wszystko ok - odblokowanie dostepu")

    # funkcja pomocnicza sluzaca do zapisywania z pamieci RAM do pliku zaszyfrowanych hasel 
    def save_to_db():
        # generowanie nowego IV 
        new_iv = crypto.generate_salt(16)
        cipher = AES256CBC(key_64, new_iv)

        serialized_vault = serialize_data(vault)
        new_ciphertext = cipher.encrypt(serialized_vault)

        mac_tag=crypto.hmac_sha_256(key_64, new_iv + new_ciphertext)
        
        output_data = {
            "crypto": {
                "salt": encode_to_base64(salt),
                "iv": encode_to_base64(new_iv),
                "mac": encode_to_base64(mac_tag)
            },
            "ciphertext": encode_to_base64(new_ciphertext)
        }

        if save_database(DB_FILE, output_data):
            print("zapisano hasla poprawnie")
            exit(0)
        else:
            print("Blad przy zapisywaniu bazy")
            exit(1)


    # glowna petla obslugujaca menu aplikacji umozliwiajaca dodanie, wyswietlenie i zapisanie hasel
    try:
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
                save_to_db()

            else:
                print("Error: Podany number spoza zakresu")

    # obsluga nacisniecia Ctrl-c aby nie utracic zmian                
    except KeyboardInterrupt:
        print("\n\nWykryto zakonczenie (Ctrl+c)")
        save_to_db()

if __name__ == "__main__":
    main()