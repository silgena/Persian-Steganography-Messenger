import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CHAR_TO_PERSIAN = {
    'A': 'من', 'B': 'تو', 'C': 'او', 'D': 'ما', 'E': 'شما', 'F': 'ایشان', 'G': 'آنها', 'H': 'مردم',
    'I': 'خورشید', 'J': 'ماه', 'K': 'ستاره', 'L': 'آسمان', 'M': 'زمین', 'N': 'دریا', 'O': 'کوه', 'P': 'دشت',
    'Q': 'رفت', 'R': 'آمد', 'S': 'دید', 'T': 'گفت', 'U': 'شنید', 'V': 'خواند', 'W': 'نوشت', 'X': 'خورد',
    'Y': 'زیبا', 'Z': 'بزرگ', 'a': 'کوچک', 'b': 'سفید', 'c': 'سیاه', 'd': 'سبز', 'e': 'قرمز', 'f': 'آبی',
    'g': 'شاد', 'h': 'غمگین', 'i': 'سریع', 'j': 'آرام', 'k': 'روز', 'l': 'شب', 'm': 'صبح', 'n': 'عصر',
    'o': 'خانه', 'p': 'مدرسه', 'q': 'کار', 'r': 'راه', 's': 'عشق', 't': 'امید', 'u': 'زندگی', 'v': 'مرگ',
    'w': 'دوست', 'x': 'دشمن', 'y': 'صلح', 'z': 'جنگ', '0': 'یک', '1': 'دو', '2': 'سه', '3': 'چهار',
    '4': 'پنج', '5': 'شش', '6': 'هفت', '7': 'هشت', '8': 'نه', '9': 'ده', '+': 'و', '/': 'در', '=': 'پایان'
}

PERSIAN_TO_CHAR = {v: k for k, v in CHAR_TO_PERSIAN.items()}


class SecretMessenger:
    def __init__(self, key_file_path, password):
        self.key = self._derive_key(key_file_path, password)
        self.cipher = Fernet(self.key)

    def _derive_key(self, key_file_path, password):
        try:
            with open(key_file_path, 'rb') as f:
                file_bytes = f.read()
        except FileNotFoundError:
            print(f"Error: Could not find {key_file_path}")
            sys.exit(1)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=file_bytes[:16],
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, message):
        encrypted_bytes = self.cipher.encrypt(message.encode())
        b64_str = base64.urlsafe_b64encode(encrypted_bytes).decode()
        persian_words = []
        for char in b64_str:
            if char in CHAR_TO_PERSIAN:
                persian_words.append(CHAR_TO_PERSIAN[char])
            else:
                persian_words.append(char)
        return " ".join(persian_words)

    def decrypt(self, persian_text):
        try:
            words = persian_text.split()
            b64_chars = []
            for word in words:
                if word in PERSIAN_TO_CHAR:
                    b64_chars.append(PERSIAN_TO_CHAR[word])

            b64_str = "".join(b64_chars)
            encrypted_bytes = base64.urlsafe_b64decode(b64_str)
            decrypted_message = self.cipher.decrypt(encrypted_bytes).decode()
            return decrypted_message
        except Exception as e:
            return f"Failed to decrypt! Check Password/Key. (Error: {e})"


def main():
    print("--- Persian Secret Messenger (File Mode) ---")

    key_path = "key.pem"
    if not os.path.exists(key_path):
        print(f"⚠️ Error: '{key_path}' not found. Please run your key generator first.")
        return

    password = input("Enter the secret password (e.g., ERFAN): ").strip()
    messenger = SecretMessenger(key_path, password)

    print("\nSelect Action:")
    print("1: Encrypt (english_text.txt -> persian_text.txt)")
    print("2: Decrypt (persian_text.txt -> english_text.txt)")
    mode = input("Choice: ").strip()

    if mode == "1":
        input_file = "english_text.txt"
        output_file = "persian_text.txt"

        if not os.path.exists(input_file):
            print(f"⚠️ Error: '{input_file}' not found. Create it and write your message inside.")
            return

        print(f"Reading from {input_file}...")
        with open(input_file, "r", encoding="utf-8") as f:
            text = f.read()

        result = messenger.encrypt(text)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result)

        print(f"✅ Success! Encrypted message saved to '{output_file}'.")

    elif mode == "2":
        input_file = "persian_text.txt"
        output_file = "english_text.txt"

        if not os.path.exists(input_file):
            print(f"⚠️ Error: '{input_file}' not found. Paste the Persian text there first.")
            return

        print(f"Reading from {input_file}...")
        with open(input_file, "r", encoding="utf-8") as f:
            persian_text = f.read()

        result = messenger.decrypt(persian_text)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result)

        print(f"✅ Success! Message decoded and saved to '{output_file}'.")
        print("Check the file to see the secret message.")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()