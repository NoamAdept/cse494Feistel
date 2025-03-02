# Feistel Cipher 🔐 (for CSE494 @ ASU)

A simple yet powerful Feistel cipher implementation in Python! Encrypt and decrypt messages with a custom number of rounds and SHA-256-based round keys.

## Features ✨
- Feistel network encryption & decryption
- Configurable number of rounds
- SHA-256 derived round keys
- Command-line interface for ease of use

## Installation ⚙️
Ensure Python 3 is installed, then:
```sh
$ git clone <repository-url>
$ cd <project-directory>
```

## Usage 🚀
Run the script with:
```sh
$ python feistel_cipher.py --plaintext <hex-encoded-text> --key <your-key> --rounds <num-rounds>
```

### Example:
```sh
$ python feistel_cipher.py --plaintext 68656c6c6f776f726c64 --key secret --rounds 10
```
**Output:**
```
Encrypted: <ciphertext-in-hex>
Decrypted: <original-plaintext-in-hex>
```

## How It Works 🛠️
1. Splits input into two halves.
2. Runs multiple Feistel rounds.
3. Uses SHA-256 for round key generation.
4. XORs halves for encryption & decryption.

## Contribute 💡
Fork, improve, and submit a PR! Open issues welcome. 

## License 📜
Open-source. Use, modify, and share freely!

