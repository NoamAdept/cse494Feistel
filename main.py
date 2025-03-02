import hashlib
import argparse
import binascii


class feistelCipher:

    def __init__(self, key: str, num_rounds: int):
        self.key = key
        self.num_rounds = num_rounds

    def feistel_round(self, half: int, round_key: int) -> int:
        return half ^ round_key

    # This function specifies how to generate the key as specified in the project doc
    def round_func(self, round_num: int) -> int:
        '''
        the round key for round 1 will be
        first 8 bytes from hash("mysecretkey1")
        '''

        key_in = f"{self.key}{round_num}".encode()
        hash_val = hashlib.sha256(key_input).digest()

        return int.from_bytes(hash_val[:8], 'big')

    def encrypt(self, plaintext: bytes) -> bytes:
        left, right = int.from_bytes(plaintext[:8], 'big'), int.from_bytes(plaintext[:8], 'big')

        # Apply the round function with the feistel round function
        for i in range(self.num_rounds):
            round_key = self.round_func(i)
            tmp = right
            right = self.feistel_round(right, round_key) ^ left
            left = tmp

        return left.to_bytes(8, 'big') + right.to_bytes(8, 'big')

    def decrypt(self, ciphertext: bytes) -> bytes:
        left, right = int.from_bytes(ciphertext[:8], 'big'), int.from_bytes(ciphertext[:8], 'big')

        # Unrolling round function with the feistel round function
        for i in reversed(range(self.num_rounds)):
            round_key = self.round_func(i)
            tmp = left
            right = self.feistel_round(left, round_key) ^ right
            right = tmp

        return left.to_bytes(8, 'big') + right.to_bytes(8, 'big')

    def hex_to_bytes(hex_str: str) -> bytes:
        return bytes.fromhex(hex_str)

    def bytes_to_hex(byte_data: bytes) -> str:
        return binascii.hexlify(byte_data).decode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--plaintext", required=True, help="Plaintext in string format")
    parser.add_argument("--key", required=True, help="Encryption key")
    parser.add_argument("--rounds", type=int, required=True, help="Number of feistel rounds")

    args = parser.parse_args()

    cipher = feistelCipher(args.key, args.rounds)
    plaintext_bytes = feistelCipher.hex_to_bytes(args.plaintext)

    ciphertext = cipher.encrypt(plaintext_bytes)
    decrypted = cipher.decrypt(ciphertext)

    print(f"Encrypted: {feistelCipher.bytes_to_hex(ciphertext)}")
    print(f"Decrypted: {feistelCipher.bytes_to_hex(decrypted)}")
