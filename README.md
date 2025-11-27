🔐 Secret Message Encryption and Decryption Using Python

A simple yet powerful Python-based tool to encrypt and decrypt secret messages using cryptographic techniques.
This project demonstrates how sensitive information can be secured using modern encryption algorithms, making it useful for beginners, students, and developers learning cybersecurity basics.

📌 Features

🔒 Encrypt any text message securely

🔓 Decrypt encrypted messages using the correct key

🗝️ Automatic key generation

📁 Key saved locally for future use

🐍 Pure Python implementation

💡 Beginner-friendly coding structure

🧰 Technologies Used

Python 3.x

cryptography library (Fernet encryption)

Install requirements:

pip install cryptography

📂 Project Structure
Secret-Message-Encryption-Decryption/
│
├── encryption.py        # Script to encrypt text
├── decryption.py        # Script to decrypt text
├── key.key              # Auto-generated encryption key
├── README.md            # Project documentation
└── sample_output.txt    # Example encrypted text

🚀 How It Works
1️⃣ Generate or Load Encryption Key

A unique key is generated using the cryptography.fernet module

Stored in a file named key.key

Used for both encryption and decryption

2️⃣ Encrypt a Message

User enters any text

The program converts it into encrypted ciphertext

Ciphertext is stored or displayed

3️⃣ Decrypt a Message

Encrypted text is converted back to original message

Requires the same key.key

📝 Usage Instructions
▶️ Encryption

Run the encryption script:

python encryption.py


Enter your secret message, and the program will output the encrypted text.

🔁 Decryption

Run the decryption script:

python decryption.py


Paste the encrypted text to retrieve the original message.

🧪 Example Output
Encryption:
Enter your message: hello world
Encrypted message:
b'gAAAAABk...'

Decryption:
Enter encrypted message:
b'gAAAAABk...'

Decrypted message: hello world

🔐 Security Notes

Never share your key.key publicly

Store encrypted files securely

Delete key if it gets exposed

For production use, rotate keys regularly

🌟 Future Enhancements

GUI interface using Tkinter

Support for file encryption & decryption

Password-protected key generation

Web-based encryption interface# Secret-message-Encryption-and-Decryption-Using-Python
