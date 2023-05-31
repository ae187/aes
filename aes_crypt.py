from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import sys

def encrypt_file(path, output_path, password):
    with open(path, "r") as file:
        data = file.read()
        iv = 16 * b'\x00'
        cipher = AES.new(derive_aes_key(password), AES.MODE_CBC, iv)
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        with open(output_path, "wb") as file:
            file.write(encrypted_data)

def decrypt_file(path, password):
    with open(path, "rb") as file:
        encrypted_data = file.read()
        iv = 16 * b'\x00'
        cipher = AES.new(derive_aes_key(password), AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode()

def derive_aes_key(str_password):
    # Derive a key from a string using PBKDF2
    salt = b'\x07\xfc\x59\xa7\x13\xd4\x07\x39\xee\x3f\xc3\x7d\x44\x8c\x36\x97'  # Generate a random salt
    iterations = 10000  # Number of iterations
    return PBKDF2(str_password, salt, dkLen=32, count=iterations)

def print_usage():
    print("python3 aes_crypt.py <[e(ncrypt)|d(ecrypt)]> <key> <input path> [<output path> (only encrypt)]")

arguments = sys.argv[1:]
if len(arguments) <3:
    print_usage()
    exit(1)

key = arguments[1]
if arguments[0] == 'e':
    if len(arguments) < 4:
        print("Invalid number of arguments for encryption")
        print_usage()
        exit(1)
    encrypt_file(arguments[2], arguments[3], key)
elif arguments[0] == 'd':
    decrypted_text = decrypt_file(arguments[2], key)
    print("Decrypted text:", decrypted_text)
else:
    print("Invalid operation: {}".format(arguments[0]))
    exit(1)
