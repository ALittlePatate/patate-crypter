from OpenSSL import crypto, SSL
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from randomness import *
import subprocess


def cert_gen(
    emailAddress=GetRandomString(10)+"@gmail.com",
    commonName=GetRandomString(10),
    countryName="NT",
    localityName=GetRandomString(10),
    stateOrProvinceName=GetRandomString(10),
    organizationName=GetRandomString(10),
    organizationUnitName=GetRandomString(10),
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "private.key",
    CERT_FILE="selfsigned.crt"):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

def sign(filename) :
    cert_gen()
    # Load the private key
    with open('private.key', 'rb') as private_key_file:
        private_key_data = private_key_file.read()
        private_key = RSA.import_key(private_key_data)

    # Load the .cert file (assuming it contains the certificate in PEM format)
    with open('selfsigned.crt', 'rb') as cert_file:
        certificate_data = cert_file.read()

    # Load the .exe file to be signed
    with open(filename, 'rb') as exe_file:
        exe_data = exe_file.read()

    # Compute the SHA-256 hash of the .exe file
    hash_obj = SHA256.new(exe_data)

    # Sign the hash using the private key
    signature = pkcs1_15.new(private_key).sign(hash_obj)

    # Save the signature to a file
    with open('signature.sig', 'wb') as signature_file:
        signature_file.write(signature)

    # Combine the .exe file and the signature
    signed_exe = exe_data + signature

    # Save the signed .exe file
    with open(filename, 'wb') as signed_exe_file:
        signed_exe_file.write(signed_exe)

    print(f"Successfully signed {filename}.")

    os.remove("selfsigned.crt")
    os.remove("private.key")
    os.remove("signature.sig")