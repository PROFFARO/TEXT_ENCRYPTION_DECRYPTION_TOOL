import os
import colorama
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import string
import numpy as np
from Crypto.Cipher import Blowfish, AES
from Crypto.PublicKey import RSA
import math
from Crypto.Cipher import AES
import base64
import hashlib
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from colorama import init, Fore, Style, Back

colorama.init()

# BLACK = "\033[30m"
##RED = "\033[31m"
# GREEN = "\033[32m"
# YELLOW = "\033[33m"
# BLUE = "\033[34m"
# MAGENTA = "\033[35m"
# CYAN = "\033[36m"
# WHITE = "\033[37m"
# RESET = "\033[0m"


def generate_key():
    return Fernet.generate_key()


def encrypt_text(text, key):
    f = Fernet(key)
    encrypted_text = f.encrypt(text.encode())
    return encrypted_text


def decrypt_text(encrypted_text, key):
    f = Fernet(key)
    decrypted_text = f.decrypt(encrypted_text).decode()
    return decrypted_text


def encrypt(key, text):
    f = Fernet(key)
    encrypted_text = f.encrypt(text.encode())
    return encrypted_text


def decrypt(key, encrypted_text):
    f = Fernet(key)
    decrypted_text = f.decrypt(encrypted_text).decode()
    return decrypted_text


def encrypt_text(plain_text, key):
    cipher_text = ""
    for letter in plain_text:
        if letter in Literals_Storages:
            index = Literals_Storages.index(letter)
            cipher_text += key[index]
        else:
            cipher_text += letter
    return cipher_text


def decrypt_text(cipher_text, key):
    plain_text = ""
    for letter in cipher_text:
        index = key.index(letter)
        plain_text += Literals_Storages[index]
    return plain_text


def encrypt_caesar(plain_text, shift):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text


def decrypt_caesar(encrypted_text, shift):
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text


Literals_Storages = " " + string.punctuation + string.ascii_letters + string.digits
Literals_Storages = list(Literals_Storages)
key = Literals_Storages.copy()
random.shuffle(key)


def generate_playfair_matrix(key):
    key = key.replace(" ", "").upper()
    key = key.replace("J", "I")  # Replace 'J' with 'I'
    key += "".join(chr(65 + i) for i in range(26))  # Add remaining letters
    key = "".join(sorted(set(key), key=key.index))  # Remove duplicates

    matrix = [key[i : i + 5] for i in range(0, len(key), 5)]
    return matrix


def find_positions(matrix, char):
    row, col = -1, -1
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                row, col = i, j
                break
    return row, col


def encrypt_playfair(plain_text, matrix):
    plain_text = plain_text.replace(" ", "").upper()
    plain_text = plain_text.replace("J", "I")  # Replace 'J' with 'I'
    encrypted_text = ""

    i = 0
    while i < len(plain_text):
        char1 = plain_text[i]
        char2 = plain_text[i + 1] if i + 1 < len(plain_text) else "X"
        row1, col1 = find_positions(matrix, char1)
        row2, col2 = find_positions(matrix, char2)

        if row1 == row2:  # Same row
            encrypted_text += (
                matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
            )
        elif col1 == col2:  # Same column
            encrypted_text += (
                matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
            )
        else:  # Forming rectangle
            encrypted_text += matrix[row1][col2] + matrix[row2][col1]

        i += 2

    return encrypted_text


def decrypt_playfair(encrypted_text, matrix):
    decrypted_text = ""

    i = 0
    while i < len(encrypted_text):
        char1 = encrypted_text[i]
        char2 = encrypted_text[i + 1]
        row1, col1 = find_positions(matrix, char1)
        row2, col2 = find_positions(matrix, char2)

        if row1 == row2:  # Same row
            decrypted_text += (
                matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            )
        elif col1 == col2:  # Same column
            decrypted_text += (
                matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            )
        else:  # Forming rectangle
            decrypted_text += matrix[row1][col2] + matrix[row2][col1]

        i += 2

    return decrypted_text


def matrix_mod_inverse(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))  # Calculate determinant
    det_inv = pow(det, -1, modulus)  # Calculate modular inverse of determinant
    matrix_inv = np.linalg.inv(matrix)  # Calculate matrix inverse
    matrix_inv = np.round(matrix_inv * det * det_inv) % modulus  # Apply modular inverse
    return matrix_inv.astype(int)


def matrix_to_numbers(matrix, alphabet):
    return [alphabet.index(char) for char in matrix]


def numbers_to_matrix(numbers, alphabet):
    return [alphabet[num] for num in numbers]


def pad_text(text, block_size, padding_char="X"):
    padding_len = block_size - len(text) % block_size
    padded_text = text + padding_char * padding_len
    return padded_text


def encrypt_hill(plain_text, key_matrix, alphabet):
    block_size = key_matrix.shape[0]
    plain_text = plain_text.upper().replace(" ", "")
    plain_text = pad_text(plain_text, block_size)

    encrypted_text = ""
    for i in range(0, len(plain_text), block_size):
        block = plain_text[i : i + block_size]
        block_numbers = matrix_to_numbers(block, alphabet)
        encrypted_block = np.dot(key_matrix, block_numbers) % len(alphabet)
        encrypted_text += "".join(numbers_to_matrix(encrypted_block, alphabet))

    return encrypted_text


def decrypt_hill(encrypted_text, key_matrix, alphabet):
    block_size = key_matrix.shape[0]
    key_matrix_inv = matrix_mod_inverse(key_matrix, len(alphabet))

    decrypted_text = ""
    for i in range(0, len(encrypted_text), block_size):
        block = encrypted_text[i : i + block_size]
        block_numbers = matrix_to_numbers(block, alphabet)
        decrypted_block = np.dot(key_matrix_inv, block_numbers) % len(alphabet)
        decrypted_text += "".join(numbers_to_matrix(decrypted_block, alphabet))

    return decrypted_text


def generate_random_key(length):
    return "".join(chr(random.randint(0, 255)) for _ in range(length))


def otp_encrypt(plain_text, key):
    encrypted_text = ""
    for i in range(len(plain_text)):
        encrypted_char = chr((ord(plain_text[i]) + ord(key[i])) % 256)
        encrypted_text += encrypted_char
    return encrypted_text


def otp_decrypt(cipher_text, key):
    decrypted_text = ""
    for i in range(len(cipher_text)):
        decrypted_char = chr((ord(cipher_text[i]) - ord(key[i])) % 256)
        decrypted_text += decrypted_char
    return decrypted_text


def columnar_transposition_encrypt(plain_text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    num_columns = len(key)
    num_rows = math.ceil(len(plain_text) / num_columns)

    matrix = [[""] * num_columns for _ in range(num_rows)]
    idx = 0

    for row in range(num_rows):
        for col in range(num_columns):
            if idx < len(plain_text):
                matrix[row][col] = plain_text[idx]
                idx += 1

    cipher_text = ""
    for col in key_order:
        cipher_text += "".join(matrix[row][col] for row in range(num_rows))

    return cipher_text


def columnar_transposition_decrypt(cipher_text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    num_columns = len(key)
    num_rows = math.ceil(len(cipher_text) / num_columns)

    matrix = [[""] * num_columns for _ in range(num_rows)]
    idx = 0

    for col in key_order:
        for row in range(num_rows):
            if idx < len(cipher_text):
                matrix[row][col] = cipher_text[idx]
                idx += 1

    plain_text = ""
    for row in range(num_rows):
        plain_text += "".join(matrix[row])

    return plain_text


def columnar_transposition_menu():
    print(f"{Fore.RED}Columnar Transposition Encryption Selected: ")
    plain_text = input(
        f"{Fore.RED}Enter the text or Sentence to be encrypted[Without punctuations]: "
    )
    key = input(
        f"{Fore.RED}Enter the encryption key[e.g.1234/2457/abcde/445786/23445]: "
    )
    encrypted_text = columnar_transposition_encrypt(plain_text, key)
    print(f"{Fore.MAGENTA}The Encrypted Text: {encrypted_text}")


def columnar_transposition_Decrypt_menu():
    print(f"{Fore.RED}Columnar Transposition Decryption Selected:")
    encrypted_text = input(
        f"{Fore.RED}Enter the text or Sentence to be Decrypted[Without punctuations]: "
    )
    key = input(
        f"{Fore.RED}Enter the encryption key[e.g.1234/2457/abcde/445786/23445]: "
    )
    decrypted_text = columnar_transposition_decrypt(encrypted_text, key)
    print(f"{Fore.MAGENTA}The Decrypted Text: {decrypted_text}")


def aes_encrypt(plain_text, key):
    # Implement AES encryption
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded_plain_text = pad(plain_text)
    encrypted_text = cipher.encrypt(padded_plain_text.encode())
    return base64.b64encode(encrypted_text).decode()


def aes_decrypt(cipher_text, key):
    # Implement AES decryption
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted_text = base64.b64decode(cipher_text)
    decrypted_text = unpad(cipher.decrypt(encrypted_text).decode())
    return decrypted_text


def pad(s):
    block_size = AES.block_size
    return s + (block_size - len(s) % block_size) * chr(
        block_size - len(s) % block_size
    )


def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


def blowfish_encrypt(plain_text, key):
    # Implement Blowfish encryption
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
    padded_plain_text = pad(plain_text)
    encrypted_text = cipher.encrypt(padded_plain_text.encode())
    return base64.b64encode(encrypted_text).decode()


def blowfish_decrypt(cipher_text, key):
    # Implement Blowfish decryption
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
    encrypted_text = base64.b64decode(cipher_text)
    decrypted_bytes = cipher.decrypt(encrypted_text)
    decrypted_text = unpad(decrypted_bytes).decode("utf-8", errors="ignore")
    return decrypted_text


def blowfish_menu():
    print(f"{Fore.RED}Blowfish Encryption Selected:")
    plain_text = input(
        f"{Fore.RED}Enter the text or Sentence to be encrypted[Without punctuations]: "
    )
    key = input(
        f"{Fore.RED}Enter the encryption key (8-56 bytes)[e.g.i am a good boy/sunday/is good/452152475/the world is grate]: "
    )
    encrypted_text = blowfish_encrypt(plain_text, key)
    encrypted_bytes = encrypted_text.encode()  # Convert the string to bytes
    print(
        f"{Fore.MAGENTA}The Encrypted Text in format"
        f"{Fore.YELLOW}(hex): {encrypted_bytes.hex()}"
    )


# Ensure 'encrypted_text' is defined before printing


def blowfish_decrypt_menu():
    print(f"{Fore.RED}Blowfish Decryption Selected:")
    encrypted_text_hex = input(
        f"{Fore.RED}Enter the encrypted text or Sentence (in hexadecimal format): "
    )
    key = input(
        f"{Fore.RED}Enter the encryption key (8-56 bytes)[e.g.i am a good boy/sunday/is good/452152475/the world is grate]: "
    )
    encrypted_text_bytes = bytes.fromhex(encrypted_text_hex)
    decrypted_text = blowfish_decrypt(encrypted_text_bytes, key)
    print(f"{Fore.MAGENTA}The Decrypted Text: {decrypted_text}")


alphabet = string.ascii_uppercase
key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])

decryption_key = None  # Initialize decryption_key outside the loop
encryption_key = None  # Initialize encryption_key outside the loop

while True:
    print(
        f"{Fore.RED}{Style.BRIGHT}\n****************{Fore.GREEN}{Style.BRIGHT}**************{Fore.YELLOW}{Style.BRIGHT}*****************{Fore.WHITE}{Style.BRIGHT}TEXT_ENCRYPTION---->@ DAYANANDA BIINDHANI @{Fore.CYAN}{Style.BRIGHT}****************{Fore.MAGENTA}{Style.BRIGHT}***************{Fore.RED}{Style.BRIGHT}*******************\n"
    )
    print(f"{Fore.RED}{Style.BRIGHT}Please choose one of the option below: ")
    print(
        f"{Fore.GREEN}{Style.BRIGHT}1. Encryption the text using letter shuffle position of the string::--->> "
    )
    print(
        f"{Fore.GREEN}{Style.BRIGHT}2. Decryption the text using letter shuffle position of the string::--->>\n"
    )
    print(
        f"{Fore.YELLOW}{Style.BRIGHT}*. Generate the Encryption key for Cryptography Method::--->>"
    )
    print(
        f"{Fore.YELLOW}{Style.BRIGHT}3. Encryption the text using the Cryptography Method::--->>"
    )
    print(
        f"{Fore.YELLOW}{Style.BRIGHT}4. Decryption the text using the Cryptography Method::--->>\n"
    )
    print(
        f"{Fore.BLUE}{Style.BRIGHT}5. Encryption the text using Caesar Cipher Method::--->>"
    )
    print(
        f"{Fore.BLUE}{Style.BRIGHT}6. Decryption the text using Caesar Cipher Method::--->>\n"
    )
    print(
        f"{Fore.MAGENTA}{Style.BRIGHT}7. Encryption the text using Playfair Cipher::--->>"
    )
    print(
        f"{Fore.MAGENTA}{Style.BRIGHT}8. Decryption the text using Playfair Cipher::--->>\n"
    )
    print(f"{Fore.CYAN}{Style.BRIGHT}9. Encryption the text using Hill Cipher::--->>")
    print(
        f"{Fore.CYAN}{Style.BRIGHT}10. Decryption the text using Hill Cipher::--->>\n"
    )
    print(
        f"{Fore.WHITE}{Style.BRIGHT}11. Encryption the text using One_Time_Pad(OTP)::--->>"
    )
    print(
        f"{Fore.WHITE}{Style.BRIGHT}12. Decryption the text using One_Time_Pad(OTP)::--->>\n"
    )
    print(
        f"{Fore.RED}{Style.BRIGHT}13. Encryption the text using Columnar_transposition::--->>"
    )
    print(
        f"{Fore.RED}{Style.BRIGHT}14. Decryption the text using Columnar_transposition::--->>\n"
    )
    print(f"{Fore.GREEN}{Style.BRIGHT}15. Encryption the text using AES::--->>")
    print(f"{Fore.GREEN}{Style.BRIGHT}16. Decryption the text using AES::--->>\n")
    print(f"{Fore.BLUE}{Style.BRIGHT}17. Encryption the text using Blowfish::--->>")
    print(f"{Fore.BLUE}{Style.BRIGHT}18. Decryption the text using Blowfish::--->>\n")
    print(f"{Fore.YELLOW}{Style.BRIGHT} 0. Exit::--->>\n")

    choice = input(f"{Fore.YELLOW}Enter your Preference::--> ")

    if choice == "1":
        plain_text = input(f"{Fore.RED}Enter the Text or sentence to be Encrypted: ")
        cipher_text = encrypt_text(plain_text, key)
        print(f"{Fore.MAGENTA}Original Message: {plain_text}")
        print(f"{Fore.MAGENTA}Encrypted Message: {cipher_text}")
    elif choice == "2":
        cipher_text_input = input(f"{Fore.RED}Enter the Cipher Text: ")
        cipher_text = cipher_text_input
        decrypted_text = decrypt_text(cipher_text, key)
        print(f"{Fore.MAGENTA}Original Cipher Text: {cipher_text_input}")
        print(f"{Fore.MAGENTA}Decrypted Message: {decrypted_text}")

    elif choice == "*":
        key = generate_key()
        print(f"{Fore.CYAN}New encryption key generated:")
        print(key.decode())

    elif choice == "3":
        key = input(f"{Fore.RED}Enter the encryption key: ").encode()
        text = input(f"{Fore.RED}Enter the text to encrypt[Without punctuations]: ")
        encrypted_text = encrypt(key, text)
        print(f"{Fore.MAGENTA}\nEncrypted text:")
        print(encrypted_text.decode())

    elif choice == "4":
        key = input(f"{Fore.RED}Enter the encryption key: ").encode()
        encrypted_text = input(f"{Fore.RED}Enter the encrypted text: ").encode()
        decrypted_text = decrypt(key, encrypted_text)
        print(f"{Fore.MAGENTA}\nDecrypted text:")
        print(decrypted_text)

    elif choice == "5":
        plain_text = input(
            f"{Fore.RED}Enter the text to be encrypted using Caesar Cipher[Without punctuations]: "
        )
        shift = int(
            input(f"{Fore.RED}Enter the shift value (integer)[e.g.5/6/4/7/87/12]: ")
        )
        encrypted_text = encrypt_caesar(plain_text, shift)
        print(f"{Fore.MAGENTA}Original Message: {plain_text}")
        print(f"{Fore.MAGENTA}Encrypted Message: {encrypted_text}")

    elif choice == "6":
        encrypted_text = input(
            f"{Fore.RED}Enter the encrypted text to be decrypted using Caesar Cipher: "
        )
        shift = int(
            input(f"{Fore.RED}Enter the shift value (integer)[e.g.5/6/4/7/87/12]: ")
        )
        decrypted_text = decrypt_caesar(encrypted_text, shift)
        print(f"{Fore.MAGENTA}Original Message: {encrypted_text}")
        print(f"{Fore.MAGENTA}Decrypted Message: {decrypted_text}")

    elif choice == "7":
        plain_text = input(
            f"{Fore.RED}Enter the text to be encrypted[Without punctuations]: "
        )
        key = input(
            f"{Fore.RED}Enter the Playfair key[e.g.hello world/car is going/(any setence)]: "
        )
        playfair_matrix = generate_playfair_matrix(key)
        encrypted_text = encrypt_playfair(plain_text, playfair_matrix)
        print(f"{Fore.MAGENTA}Encrypted Text: {encrypted_text}")

    elif choice == "8":
        encrypted_text = input(f"{Fore.RED}Enter the text to be decrypted: ")
        key = input(
            f"{Fore.RED}Enter the Playfair key[e.g.hello world/car is going/(any setence)]: "
        )
        playfair_matrix = generate_playfair_matrix(key)
        decrypted_text = decrypt_playfair(encrypted_text, playfair_matrix)
        print(f"{Fore.MAGENTA}Decrypted Text: {decrypted_text}")

    elif choice == "9":
        plain_text = input(
            f"{Fore.RED}Enter the text to be encrypted[Without punctuations]: "
        )
        alphabet = string.ascii_uppercase
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])

        encrypted_text = encrypt_hill(plain_text, key_matrix, alphabet)
        print(f"{Fore.MAGENTA}Encrypted Text: {encrypted_text}")

    elif choice == "10":
        encrypted_text = input(f"{Fore.RED}Enter the text to be decrypted: ")
        alphabet = string.ascii_uppercase
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])

        decrypted_text = decrypt_hill(encrypted_text, key_matrix, alphabet)
        print(f"{Fore.MAGENTA}Decrypted Text: {decrypted_text}")

    elif choice == "11":
        plain_text = input(
            f"{Fore.RED}Enter the text to be encrypted[Without punctuations]: "
        )
        key = generate_random_key(len(plain_text))
        encrypted_text = otp_encrypt(plain_text, key)
        print(f"{Fore.CYAN}Key: {key}")
        print(f"{Fore.MAGENTA}Encrypted Text: {encrypted_text}")

    elif choice == "12":
        cipher_text = input(f"{Fore.RED}Enter the text to be decrypted: ")
        key = input(f"{Fore.RED}Enter the key used for encryption: ")
        decrypted_text = otp_decrypt(cipher_text, key)
        print(f"{Fore.MAGENTA}Decrypted Text: {decrypted_text}")

    elif choice == "13":
        columnar_transposition_menu()

    elif choice == "14":
        columnar_transposition_Decrypt_menu()

    elif choice == "15":
        plain_text = input(
            f"{Fore.RED}Enter the text to be encrypted[Without punctuations]: "
        )
        key = input(
            f"{Fore.RED}Enter the encryption key (16/24/32 bytes)[ThisIsASecretKey(16 bytes)/SuperSecureKey1234567890ABCD(24 bytes)/VeryStrongEncryptionKey1234567890123456(32 bytes)]: "
        )
        encrypted_text = aes_encrypt(plain_text, key)
        print(f"{Fore.MAGENTA}Encrypted Text: {encrypted_text}")

    elif choice == "16":
        cipher_text = input(f"{Fore.RED}Enter the text to be decrypted: ")
        key = input(
            f"{Fore.RED}Enter the decryption key (16/24/32 bytes)[ThisIsASecretKey(16 bytes)/SuperSecureKey1234567890ABCD(24 bytes)/VeryStrongEncryptionKey1234567890123456(32 bytes)]: "
        )
        decrypted_text = aes_decrypt(cipher_text, key)
        print(f"{Fore.MAGENTA}Decrypted Text: {decrypted_text}")

    elif choice == "17":
        blowfish_menu()

    elif choice == "18":
        blowfish_decrypt_menu()

    elif choice == "0":
        print(
            f"\n{Fore.BLUE}{Style.BRIGHT}B{Fore.RED}{Style.BRIGHT}y{Fore.GREEN}{Style.BRIGHT}e{Fore.CYAN}{Style.BRIGHT} B{Fore.BLUE}{Style.BRIGHT}u{Fore.YELLOW}{Style.BRIGHT}d{Fore.CYAN}{Style.BRIGHT}d{Fore.MAGENTA}{Style.BRIGHT}y{Fore.GREEN}{Style.BRIGHT} n{Fore.CYAN}{Style.BRIGHT}i{Fore.MAGENTA}{Style.BRIGHT}c{Fore.RED}{Style.BRIGHT}e{Fore.BLUE}{Style.BRIGHT} t{Fore.GREEN}{Style.BRIGHT}o{Fore.WHITE}{Style.BRIGHT} w{Fore.RED}{Style.BRIGHT}o{Fore.GREEN}{Style.BRIGHT}r{Fore.BLUE}{Style.BRIGHT}k{Fore.YELLOW}{Style.BRIGHT} w{Fore.BLUE}{Style.BRIGHT}i{Fore.CYAN}{Style.BRIGHT}t{Fore.YELLOW}{Style.BRIGHT}h{Fore.RED}{Style.BRIGHT} y{Fore.MAGENTA}{Style.BRIGHT}o{Fore.RED}{Style.BRIGHT}u{Fore.CYAN}...E{Style.BRIGHT}{Fore.GREEN}{Style.BRIGHT}x{Fore.BLUE}{Style.BRIGHT}i{Fore.WHITE}{Style.BRIGHT}t{Fore.GREEN}{Style.BRIGHT}i{Fore.RED}{Style.BRIGHT}n{Fore.YELLOW}{Style.BRIGHT}g{Fore.CYAN}{Style.BRIGHT}....\n"
        )
        break
    else:
        print("\nInvalid Choice")
