from certy import Credential

ca = Credential().subject("CN=ca")
ca.write_certificates_as_pem("ca.pem")

cred = (
    Credential()
    .subject("CN=server")
    .issuer(ca)
    .subject_alt_names("DNS:app.127.0.0.1.nip.io")
)
cred.write_certificates_as_pem("cert.pem")
cred.write_private_key_as_pem("key.pem")
