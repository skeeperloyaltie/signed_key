import socket
import ssl
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import datetime
import os
import resource
import time

# Assume AES key and IV are shared securely between client and server
# For this example, we're defining them directly for simplicity
key = os.urandom(32)  # AES-256 key
iv = os.urandom(16)  # Initialization vector

# Decrypt a message
def decrypt_message(encrypted_message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message


def generate_self_signed_cert(cert_path, key_path):
    # Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write certificate and private key to files
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    print("Certificate and private key have been generated and saved.")

def server(cert_path, key_path, key, iv):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    bindsocket = socket.socket()
    bindsocket.bind(('localhost', 8443))
    bindsocket.listen(5)
    
    print("Server is listening on port 8443...")
    while True:
        newsocket, fromaddr = bindsocket.accept()
        conn = context.wrap_socket(newsocket, server_side=True)
        try:
            print("Connection received from", fromaddr)
            while True:
                encrypted_data = conn.recv(1024)
                if not encrypted_data:
                    break

                print('Received encrypted data:', repr(encrypted_data))

                # Start measuring time and resources
                time_start = time.perf_counter()

                decrypted_data = decrypt_message(encrypted_data, key, iv)
                print("Decrypted data:", repr(decrypted_data))

                conn.sendall(encrypted_data)

                
        finally:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()



# Initialization and server thread start remain the same
cert_path = "selfsigned_certificate.pem"
key_path = "private_key.pem"
generate_self_signed_cert(cert_path, key_path)

server_thread = threading.Thread(target=server, args=(cert_path, key_path, key, iv))
server_thread.start()
time_start = time.perf_counter()



time_elapsed = (time.perf_counter() - time_start)
memMb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024.0/1024.0
print ("%5.1f secs %5.1f MByte" % (time_elapsed,memMb))