import socket
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate a random key and IV for AES encryption
# In a real application, ensure you have a secure way to share or agree on these between client and server
key = os.urandom(32)  # AES-256 requires a 32-byte key
iv = os.urandom(16)  # AES block size for CFB mode is 16 bytes

# Encrypt a message
def encrypt_message(message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message

def client(key, iv):
    # Prepare the message
    original_message = b"Hello, world"
    encrypted_message = encrypt_message(original_message, key, iv)

    # SSL Context setup
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Establish a secure connection and send the encrypted message
    with socket.create_connection(('localhost', 8443)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as sslsock:
            sslsock.sendall(encrypted_message)  # Send encrypted data
            response = sslsock.recv(1024)
            # Assuming the server echoes the encrypted message back
            decrypted_response = decrypt_message(response, key, iv)
            print("Decrypted response from server:", decrypted_response)

# Pass the key and IV to the client function
client(key, iv)
