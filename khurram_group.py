import time
import resource
import ssl
import socket
import pem
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

time_start = time.perf_counter()
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Create a self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

certificate = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Our certificate will be valid for 10 days
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
    # Sign our certificate with our private key
).sign(private_key, hashes.SHA256(), default_backend())

# Write our certificate and key to disk
with open("selfsigned_certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("Certificate and private key have been generated and saved.")


# Load the certificate and key files (replace with actual paths)
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# context = ssl._create_unverified_context()

context.load_cert_chain(certfile="selfsigned_certificate.pem", keyfile="private_key.pem")

# Establish TLS connection
def establish_tls_connection():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 8443))
    ssl_connection = context.wrap_socket(sock, server_hostname="localhost")
    return ssl_connection

# Perform AES-GCM encryption
def aes_encryption(data, ssl_conn):
    try:
        ssl_conn.sendall(data)
        encrypted_data = ssl_conn.recv(1024)
        return encrypted_data
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None

# Perform AES-GCM decryption
def aes_decryption(encrypted_data, ssl_conn):
    try:
        ssl_conn.sendall(encrypted_data)
        decrypted_data = ssl_conn.recv(1024)
        return decrypted_data
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None

# Server code
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 8443))
    server_socket.listen(1)
    print("Server is listening on port 8443...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection received from {address}")
        data = client_socket.recv(1024)
        print("Received data:", data)

        # Echo back the received data
        client_socket.sendall(data)
        client_socket.close()

# Start the server in a separate thread
server_thread = threading.Thread(target=server)
server_thread.start()


# Encryption and Decryption
ssl_connection = establish_tls_connection()
plaintext = b"Hello, world"
encrypted_data = aes_encryption(plaintext, ssl_connection)
if encrypted_data:
    decrypted_data = aes_decryption(encrypted_data, ssl_connection)
    print("Decrypted data:", decrypted_data)
# Close the connection
ssl_connection.close()
time_elapsed = (time.perf_counter() - time_start)
memMb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024.0/1024.0
print ("%5.1f secs %5.1f MByte" % (time_elapsed,memMb))
