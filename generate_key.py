import os
import base64


def generate_secure_key_file(filename="key.pem"):
    random_bytes = os.urandom(64)
    secure_content = base64.urlsafe_b64encode(random_bytes).decode('utf-8')

    with open(filename, "w") as f:
        f.write(secure_content)

    print(f"✅ Success! Generated a secure key file: {filename}")
    print(f"🔒 Keep this file safe. Share it ONLY with your friend.")
    print(f"📄 Preview of key content: {secure_content[:20]}...")


if __name__ == "__main__":
    if os.path.exists("key.pem"):
        choice = input("⚠️ 'key.pem' already exists! Overwrite it? (y/n): ")
        if choice.lower() == 'y':
            generate_secure_key_file()
        else:
            print("Operation cancelled.")
    else:
        generate_secure_key_file()