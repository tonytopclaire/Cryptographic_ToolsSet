from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import datetime
import base64
import os
from cryptography.fernet import Fernet

usecase = {
    "create_csr": "Usecase: These X.509 certificates are used to authenticate clients and servers; commonly used for web servers that use HTTPS. The Certificate Authority (CA) allows you to obtain a certificate following these steps below:\n1. Private/public key pair is generated.\n2. Request for a certificate is created; signed by your key to prove its yours.\n3. CSR is then given to a CA without the private key..\n4. The resource you want a certificate for is validated by the CA.\n5. Certificate is then signed and given to you by the CA. (Includes public key & resource)\n6. Server is formed to use the certificate; sharing your private key to server traffic.\n\n",
    "create_self_signed_csr": "Usecase: In the previous task, in order to create a CSR, it was required to get it signed by the CA. This is not the case when you create a self-signed certificate. The private key is used to sign it instead by conforming to the assigned public key. However, a self-signed certificate is not trustworthy like a CSR. Although, self-signed certificates are generally used for local testing and can be easily issued effortlessly. Hence, trust is not the main priority for a self-signed certificate.\n\n",
    "passwords_with_fernet": "Fernet implements symmetric encryption authenticated messages. Thus, the message can’t be deployed or read without the secret key. Passwords are also an available option with Fernet if needed. Key derivation functions such as PBKDF2HMAC, Scrypt and bcrypt are capable of making this possible. Down below you can see the main library used for Fernet.\n\n",
    "hash_based_mac": "Hash-based message authentication codes allow you to validate the integrity and authenticity of a message. HMACs also let you calculate message authentication codes with a cryptographic hash function paired with a key. Down below you can see the main libraries used for HMAC.\n\n",
    "symmetric_aes": "In order to encrypt or conceal the sender and receivers’ content, the same secret key needs to be used mutually. One disadvantage of Symmetric encryption is that it only provides secrecy but not authenticity. AES (Advanced Encryption Standard) is a great default option for encryption because it is secure and very fast. Down below you can see the main libraries used.\n\n",
}


def create_csr():
    print(usecase["create_csr"])
    print("Starting the process....")
    # Generate our key
    print("Generating private key....")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write our key to disk for safe keeping
    print("Writing private key to path ./csr/key.pem file....")
    with open("./csr/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Generate a CSR
    print("Generating CSR....")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
            x509.DNSName(u"subdomain.mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    # Write our CSR out to disk.
    print("Writing CSR to path ./csr/csr.pem....")
    with open("./csr/csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(
        "Now you can give CSR to Certificate Authority (CA), who will give certificate to you in return")
    user_input = int(input("Would you like to see the public values n and e?\nPress 0 for No and 1 for Yes: "))
    if user_input:
        print(key.public_key().public_numbers())


def create_self_signed_csr():
    print(usecase["create_self_signed_csr"])
    print("Starting the process....")
    # Generate our key
    print("Generating private key....")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write our key to disk for safe keeping
    print("Writing private key to path ./self-signed-csr/key.pem file....")
    with open("./self-signed-csr/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    print("Generating Certificate, and signing with the private key....")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
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
    ).sign(key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    print("Writing Certificate to path ./self-signed-csr/certificate.pem....")
    with open("./self-signed-csr/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Now you have a private key and certificate that can be used for local testing")
    user_input = int(input("Would you like to see the public values n and e?\nPress 0 for No and 1 for Yes: "))
    if user_input:
        print(key.public_key().public_numbers())


def passwords_with_fernet():
    print(usecase["passwords_with_fernet"])
    print("Starting the process....")
    print("Using the password as `mypassword` for encryption with fernet....")
    password = b"mypassword"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    print("Generating the key using password....")
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    plain_text = input("Enter message that you want to encrypt: ")
    print("Encrypting plain text: {0:s}....".format(plain_text))
    token = f.encrypt(plain_text.encode('utf-8'))
    print("Encrypted text is: {0:s}\nDecrypting the text....".format(token.decode("utf-8")))
    recovered_text = f.decrypt(token)
    print("Decrypted text: {0:s}".format(recovered_text.decode("utf-8")))


def hash_based_mac():
    print(usecase["hash_based_mac"])
    key = input("Enter the key you want to use with HMAC: ")
    print("Generating the HMAC object....")
    h = hmac.HMAC(key.encode("utf-8"), hashes.SHA256(), backend=default_backend())
    message = input("Enter the message that you want to hash: ")
    h.update(message.encode("utf-8"))
    hash = h.finalize()
    print("The hash of the {0:s} is: ".format(message))
    print(hash)


def symmetric_aes():
    print(usecase["symmetric_aes"])
    print("Starting the process....")
    backend = default_backend()
    print("Generating the key and IV for the AES....")
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    plain_text = input("Enter the message you want to encrypt: ")
    if len(plain_text) % 32 != 0:
        print(
            "Since size of plain text is not multiple of block length 32 bytes, adding trailing zeroes to plain text....")
        plain_text = plain_text + (32 - (len(plain_text) % 32)) * "0"
        print("Modified plain text: {0:s}".format(plain_text))
    cipher_text = encryptor.update(plain_text.encode("utf-8")) + encryptor.finalize()
    print("Cipher text:")
    print(cipher_text)
    print("Decrypting the cipher text....")
    decryptor = cipher.decryptor()
    recovered_text = decryptor.update(cipher_text) + decryptor.finalize()
    recovered_text = recovered_text.decode("utf-8").strip("0")
    print("Recovered text: {0:s}".format(recovered_text))
    user_input = int(input("Do you want to see the IV and Key of AES algorithm?\nPress 0 for No and 1 for Yes: "))
    if user_input:
        print("key: ", key, "\niv: ", iv)


if __name__ == '__main__':
    tasks = {
        1: create_csr,
        2: create_self_signed_csr,
        3: passwords_with_fernet,
        4: hash_based_mac,
        5: symmetric_aes,
    }
    while True:
        print(
            "\nWelcome to the basic command line ‐ based “Swiss Army cryptographic toolset for beginners”. Different tasks available are below:")
        print(
            "Press 1 to Create a Certificate Signing Request (CSR)\nPress 2 to Create a self-signed certificate\nPress 3 to Encrypt a symmetric authenticated message via Fernet\nPress 4 to Generate a Hash-based message using HMAC\nPress 5 to Encrypt a message via AES\n\nPress 0 to exit")
        number = int(input("Select task number you want to implement: "))
        if number == 0:
            print("Exiting the program....")
            break
        if number not in tasks:
            print("Invalid input try again....")
            continue
        print()
        tasks[number]()
