1. Prerequisites 
Ensure you have Python 3.x installed. Install the encryption library using:

```bash
pip install -r requirements.txt
```

2. Initial Setup
You need a "Key File" to lock and unlock messages:

Run:
```bash
python generate_key.py
```

A file named key.pem will be generated.

Crucial: Share this key.pem file with your friend privately. Both parties must use the exact same file.

3. How to Encrypt (Sending)
Type your message in english_text.txt.

Run the script: 

```bash
python secret_message.py
```

Enter your secret password (e.g., ERFAN).

Select Option 1 (Encrypt).

The Persian ciphertext will be saved in persian_text.txt. Send this text to your friend.

4. How to Decrypt
Paste the received Persian text into persian_text.txt.

Run the script: 

```bash
python secret_message.py
```

Enter the secret password shared by the sender.

Select Option 2 (Decrypt).

Read the original message in english_text.txt.

5. Security Summary
This system uses AES-256 (Fernet). It is secure because it requires both "Something you have" (the key.pem file) and "Something you know" (the password).