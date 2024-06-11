import base64
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.hazmat.primitives import hashes, serialization
import os
from dotenv import load_dotenv

# Load environment variables from ~/.ssh/.env
load_dotenv('/Users/leon/.ssh/.env')

cert_password = os.getenv('CERTPASSWORD')
# Update with your actual certificate path
CERTNAME = os.getenv('CERTNAME')
cert_path = f"/Users/leon/.ssh/{CERTNAME}.p12"

# Host and signing data for the API call
host = os.getenv('HOST')
signing_data = "/api/mdm/devices/search"
url = f"https://{host}{signing_data}"

# Read the certificate file
with open(cert_path, 'rb') as certfile:
    cert = certfile.read()

# Load the key and certificate
key, certificate, additional_certs = pkcs12.load_key_and_certificates(cert, cert_password.encode())

# Define PKCS#7 signing options
options = [pkcs7.PKCS7Options.DetachedSignature]

# Create the signed data
signed_data = pkcs7.PKCS7SignatureBuilder() \
    .set_data(signing_data.encode("UTF-8")) \
    .add_signer(certificate, key, hashes.SHA256()) \
    .sign(serialization.Encoding.DER, options)

# Encode the signed data in base64
signed_data_b64 = base64.b64encode(signed_data).decode()

# here is a table of the headers
print(f"""
------------------------------------
Name           | Value
------------------------------------
User-Agent     | {os.getenv('USER')}
aw-tenant-code | {os.getenv('APIKEY')}
Host           | {host}
Authorization  | CMSURL'1 {signed_data_b64}
Accept         | application/json
version        | 1
""")
