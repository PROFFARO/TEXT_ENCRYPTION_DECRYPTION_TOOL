from cryptography.fernet import Fernet
import os
import colorama
from colorama import init, Fore, Style, Back

colorama.init()


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


def main():
    print(
        f"{Fore.BLUE}{Style.BRIGHT}****************{Fore.YELLOW}{Style.BRIGHT}*************{Fore.GREEN}{Style.BRIGHT}@CREATED BY--->DAYANANDA BINDHANI@{Fore.RED}{Style.BRIGHT}**************{Fore.CYAN}{Style.BRIGHT}*******************"
    )
    while True:
        print(
            f"{Fore.RED}Select an option from below:\n1. Encrypt the Text from the text_file::--->>\n2. Decrypt the Text from the text_file::--->>\n0. Exit\n"
        )

        choice = input(f"{Fore.YELLOW}Enter your Preference::--> ")

        if choice == "0":
            print(
                f"\n{Fore.BLUE}{Style.BRIGHT}B{Fore.RED}{Style.BRIGHT}y{Fore.GREEN}{Style.BRIGHT}e{Fore.CYAN}{Style.BRIGHT} B{Fore.BLUE}{Style.BRIGHT}u{Fore.YELLOW}{Style.BRIGHT}d{Fore.CYAN}{Style.BRIGHT}d{Fore.MAGENTA}{Style.BRIGHT}y{Fore.GREEN}{Style.BRIGHT} n{Fore.CYAN}{Style.BRIGHT}i{Fore.MAGENTA}{Style.BRIGHT}c{Fore.RED}{Style.BRIGHT}e{Fore.BLUE}{Style.BRIGHT} t{Fore.GREEN}{Style.BRIGHT}o{Fore.WHITE}{Style.BRIGHT} w{Fore.RED}{Style.BRIGHT}o{Fore.GREEN}{Style.BRIGHT}r{Fore.BLUE}{Style.BRIGHT}k{Fore.YELLOW}{Style.BRIGHT} w{Fore.BLUE}{Style.BRIGHT}i{Fore.CYAN}{Style.BRIGHT}t{Fore.YELLOW}{Style.BRIGHT}h{Fore.RED}{Style.BRIGHT} y{Fore.MAGENTA}{Style.BRIGHT}o{Fore.RED}{Style.BRIGHT}u{Fore.CYAN}...E{Style.BRIGHT}{Fore.GREEN}{Style.BRIGHT}x{Fore.BLUE}{Style.BRIGHT}i{Fore.WHITE}{Style.BRIGHT}t{Fore.GREEN}{Style.BRIGHT}i{Fore.RED}{Style.BRIGHT}n{Fore.YELLOW}{Style.BRIGHT}g{Fore.CYAN}{Style.BRIGHT}....\n"
            )
            break

        elif choice == "1":
            key = generate_key()
            print(f"{Fore.RED}The Secured Generated Key:{Fore.MAGENTA}  {key.decode()}")

            file_path = input(
                f"{Fore.YELLOW}Enter the path of the text file where the text contains{Fore.GREEN}[e.g. path\\to\\text.txt(without double inverted comma)]: "
            )

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                    text = file.read()
            except Exception as e:
                print(f"{Fore.BLUE}Error reading the file:", e)
                continue

            encrypted_text = encrypt_text(text, key)

            try:
                with open(file_path, "wb") as file:
                    file.write(encrypted_text)
                print(
                    f"{Fore.BLUE}Text encrypted successfuly and overwritten inside the file."
                )
            except Exception as e:
                print(f"{Fore.BLUE}Error writing encrypted text:", e)

        elif choice == "2":
            key = input(f"{Fore.YELLOW}Enter the secure decryption key: ")
            f = Fernet(key.encode())

            file_path = input(
                f"{Fore.YELLOW}Enter the path of the encrypted text file[e.g. path\\to\\text.txt(without double inverted comma)]: "
            )

            try:
                with open(file_path, "rb") as file:
                    encrypted_text = file.read()
            except Exception as e:
                print(f"{Fore.BLUE}Error reading the file:", e)
                continue

            try:
                decrypted_text = decrypt_text(encrypted_text, key.encode())
                print(f"{Fore.BLUE}The Decrypted Text: {decrypted_text}")
            except Exception as e:
                print(f"{Fore.BLUE}Error decrypting text:", e)

        else:
            print(f"{Fore.BLUE}Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()
