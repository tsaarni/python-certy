import os
import ssl
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

import requests

from certy import Credential


def serve_https(server_cert_path, server_key_path, client_root_ca_path):
    # Create SSLContext for the server.
    # Require client to present certificate, signed by the client root CA.
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH, cafile=client_root_ca_path
    )
    context.verify_mode = ssl.CERT_REQUIRED

    # Load server certificate and private key.
    context.load_cert_chain(certfile=server_cert_path, keyfile=server_key_path)

    http = HTTPServer(("localhost", 8443), SimpleHTTPRequestHandler)
    http.socket = context.wrap_socket(http.socket, server_side=True)
    http.serve_forever()


# Create root CA and intermediate CA for issuing server certificate.
server_root_ca_cred = Credential().subject("CN=server-root-ca")
# Certy does not recognize intermediate CA as CA since it is not self-signed.
# ca() needs to be called explicitly to prepare the certificate as CA cert.
server_intermediate_ca_cred = (
    Credential().subject("CN=server-intermediate-ca").issuer(server_root_ca_cred).ca()
)

# Create root CA for issuing client certificate.
client_root_ca_cred = Credential().subject("CN=client-root-ca")

# Create a server certificate, issued by the intermediate server CA.
server_cred = (
    Credential()
    .subject("CN=localhost")
    .subject_alt_names("DNS:app.127.0.0.1.nip.io")
    .issuer(server_intermediate_ca_cred)
)

# Create a client certificate, issued by the server root CA.
client_cred = Credential().subject("CN=client").issuer(client_root_ca_cred)

# Write the certificates and keys to disk.
server_root_ca_cred.write_certificates_as_pem("server-root-ca.pem")
server_cred.write_certificates_as_pem(
    "server.pem"
)  # server.pem bundle includes chain: server cert, intermediate CA (in that order).
server_cred.write_private_key_as_pem("server-key.pem")
client_root_ca_cred.write_certificates_as_pem("client-root-ca.pem")
client_cred.write_certificates_as_pem("client.pem")
client_cred.write_private_key_as_pem("client-key.pem")

# Start a HTTPS server in a separate thread.
threading.Thread(
    target=serve_https,
    args=(
        "server.pem",  # server_cert_path
        "server-key.pem",  # server_key_path
        "client-root-ca.pem",  # client_root_ca_path
    ),
).start()

# Make a request to the HTTPS server.
# Use the client certificate and key for mutual TLS authentication.
response = requests.get(
    "https://app.127.0.0.1.nip.io:8443",
    verify="server-root-ca.pem",
    cert=("client.pem", "client-key.pem"),
)

# Print the response.
print(response.text)
