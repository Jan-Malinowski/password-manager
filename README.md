# Lokalny Menedżer Haseł

Projekt realizowany w ramach przedmiotu Kryptografia na studiach I stopnia na kierunku Cyberbezpieczeństwo na Akademii Górniczo-Hutniczej w Krakowie.

**O projekcie:**

Aplikacja to bezpieczny, lokalny menedżer haseł, który przechowuje poufne dane użytkownika w zaszyfrowanym pliku JSON. 

Głównym założeniem i wyzwaniem projektu jest własnoręczna implementacja mechanizmów kryptograficznych od zera. Projekt ma na celu dogłębne zrozumienie matematyki i logiki stojącej za standardami kryptograficznymi, w tym operacji na ciele Galois, rozszerzania klucza oraz trybów łańcuchowych.

**Główne funkcjonalności i implementacja:**

W ramach projektu samodzielnie zaimplementujemy następujące algorytmy i mechanizmy:
1. Rdzeń AES-256 (Advanced Encryption Standard): Implementacja operacji na blokach (SubBytes, ShiftRows, MixColumns, AddRoundKey) oraz Key Expansion.
2. Tryb CBC (Cipher Block Chaining): Dzielenie wiadomości na bloki i wykorzystanie wektorów inicjalizujących (IV).
3. Padding PKCS7: Mechanizm dopełniania bloków danych do 16 bajtów.
4. PBKDF2-HMAC-SHA256: Funkcja derywacji klucza wyprowadzająca 256-bitowy klucz z hasła głównego (Master Password) przy użyciu losowej soli.
5. Zarządzanie danymi (JSON): Bezpieczny zapis i odczyt zserializowanych, zaszyfrowanych danych (sól, IV, szyfrogram) na dysku lokalnym.

**Stos technologiczny:**

Język: Python 3

Kryptografia: Standardowa biblioteka Pythona (hashlib, hmac, os.urandom) + własne implementacje.

Baza danych: Moduł json, kodowanie base64.

Interfejs: CustomTkinter
