#
# Copyright Certy Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import datetime
import ipaddress
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID

from certy import Credential, ExtendedKeyUsage, KeyType, KeyUsage


def test_subject_name():
    cert = Credential().subject("CN=test").generate().get_certificate()
    assert cert.subject.rfc4514_string() == "CN=test"
    assert cert.issuer.rfc4514_string() == "CN=test"


def test_subject_alt_name():
    cert = (
        Credential()
        .subject("CN=test")
        .subject_alt_names("DNS:host.example.com", "URI:http://www.example.com", "IP:1.2.3.4")
        .generate()
        .get_certificate()
    )
    assert cert.subject.rfc4514_string() == "CN=test"
    assert cert.issuer.rfc4514_string() == "CN=test"
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == x509.SubjectAlternativeName(
        [
            x509.DNSName("host.example.com"),
            x509.UniformResourceIdentifier("http://www.example.com"),
            x509.IPAddress(ipaddress.IPv4Address("1.2.3.4")),
        ]
    )

    # Single subject alternative name given instead of list.
    cert = Credential().subject("CN=test").subject_alt_names("DNS:host.example.com").generate().get_certificate()
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == x509.SubjectAlternativeName(
        [x509.DNSName("host.example.com")]
    )


def test_default_key_size():
    cred = Credential().subject("CN=test").generate()
    assert key_must_be(cred, ec.EllipticCurvePrivateKey, 256)
    cred = Credential().subject("CN=test").key_type(KeyType.RSA).generate()
    assert key_must_be(cred, rsa.RSAPrivateKey, 2048)


def test_ec_key_sizes():
    cred = Credential().subject("CN=test").key_size(256).generate()
    assert key_must_be(cred, ec.EllipticCurvePrivateKey, 256)
    cred.key_size(384).generate()
    assert key_must_be(cred, ec.EllipticCurvePrivateKey, 384)
    cred.key_size(521).generate()
    assert key_must_be(cred, ec.EllipticCurvePrivateKey, 521)


def test_rsa_key_sizes():
    cred = Credential().subject("CN=test").key_type(KeyType.RSA).key_size(1024).generate()
    assert key_must_be(cred, rsa.RSAPrivateKey, 1024)
    cred.key_size(2048).generate()
    assert key_must_be(cred, rsa.RSAPrivateKey, 2048)
    cred.key_size(4096).generate()
    assert key_must_be(cred, rsa.RSAPrivateKey, 4096)


def test_ed25519_certificate():
    # Ed25519 has fixed key size, so key_size() should not be used.
    cred = Credential().subject("CN=test").key_type(KeyType.ED25519).generate()
    isinstance(cred.get_private_key(), ed25519.Ed25519PrivateKey)


def test_expires():
    cred = Credential().subject("CN=test").expires(timedelta(days=365)).generate()
    cert = cred.get_certificate()
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=365)


def test_key_usages():
    cert = Credential().subject("CN=joe").generate().get_certificate()
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value == x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )

    cert = Credential().subject("CN=joe").ca(False).generate().get_certificate()
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value == x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    cert = (
        Credential()
        .subject("CN=joe")
        .key_usages(
            KeyUsage.DIGITAL_SIGNATURE,
            KeyUsage.NON_REPUDIATION,
            KeyUsage.KEY_ENCIPHERMENT,
            KeyUsage.DATA_ENCIPHERMENT,
            KeyUsage.KEY_AGREEMENT,
            KeyUsage.KEY_CERT_SIGN,
            KeyUsage.CRL_SIGN,
            KeyUsage.ENCIPHER_ONLY,
            KeyUsage.DECIPHER_ONLY,
        )
        .generate()
        .get_certificate()
    )
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value == x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=True,
        key_agreement=True,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=True,
        decipher_only=True,
    )


def test_extended_key_usages():
    cert = Credential().subject("CN=joe").generate().get_certificate()
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)

    cert = (
        Credential()
        .subject("CN=joe")
        .ext_key_usages(
            ExtendedKeyUsage.CLIENT_AUTH,
            ExtendedKeyUsage.SERVER_AUTH,
        )
        .generate()
        .get_certificate()
    )

    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage(
        [
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]
    )


def test_issuer():
    ca = Credential().subject("CN=ca")
    cert = Credential().subject("CN=joe").issuer(ca).generate().get_certificate()
    assert cert.subject.rfc4514_string() == "CN=joe"
    assert cert.issuer.rfc4514_string() == "CN=ca"


def test_ca():
    cert = Credential().subject("CN=ca").generate().get_certificate()
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca == True
    cert = Credential().subject("CN=end-entity").ca(False).generate().get_certificate()
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca == False


def test_intermediate_ca():
    root_ca = Credential().subject("CN=root-ca")
    intermediate_ca = Credential().subject("CN=intermediate-ca").issuer(root_ca).ca()
    certs = Credential().subject("CN=joe").issuer(intermediate_ca).generate().get_certificates()
    assert len(certs) == 2
    assert certs[0].subject.rfc4514_string() == "CN=joe"
    assert certs[1].subject.rfc4514_string() == "CN=intermediate-ca"

    certs = intermediate_ca.generate().get_certificates()
    assert len(certs) == 1
    assert certs[0].subject.rfc4514_string() == "CN=intermediate-ca"


def test_not_before_and_not_after():
    want_not_before = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    want_not_after = datetime(2023, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    cert = (
        Credential()
        .subject("CN=joe")
        .not_before(want_not_before)
        .not_after(want_not_after)
        .generate()
        .get_certificate()
    )
    assert cert.not_valid_before_utc == want_not_before
    assert cert.not_valid_after_utc == want_not_after

    expires = timedelta(days=365)
    cert = Credential().subject("CN=joe").expires(expires).generate().get_certificate()
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == expires


def test_serial_number():
    cert = Credential().subject("CN=joe").serial(1345).generate().get_certificate()
    assert cert.serial_number == 1345

    # serial number should be unique, evem if not specified by the user
    cert1 = Credential().subject("CN=joe").generate().get_certificate()
    cert2 = Credential().subject("CN=jen").generate().get_certificate()
    assert cert1.serial_number != cert2.serial_number


def test_crl_distribution_point_uri():
    cert = Credential().subject("CN=joe").crl_distribution_point_uri("http://example.com/crl").get_certificate()
    assert (
        cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value
        == "http://example.com/crl"
    )


def test_certificate_as_pem():
    cred = Credential().subject("CN=joe").generate()
    cert = cred.get_certificate()
    pem = cred.get_certificate_as_pem()
    assert cert == x509.load_pem_x509_certificate(pem)


def test_privatekey_as_pem():
    cred = Credential().subject("CN=test").generate()
    key = cred.get_private_key()
    pem = cred.get_private_key_as_pem()
    loaded = serialization.load_pem_private_key(pem, None)
    assert private_keys_equal(key, loaded)


def test_write_pem_files(tmp_path):
    wanted = Credential().subject("CN=joe").generate()
    wanted.write_certificates_as_pem(tmp_path / "joe.pem")
    wanted.write_private_key_as_pem(tmp_path / "joe-key.pem")

    # Load certificate and key from files.
    got_cert = x509.load_pem_x509_certificate((tmp_path / "joe.pem").read_bytes())
    got_key = serialization.load_pem_private_key((tmp_path / "joe-key.pem").read_bytes(), None)

    # Check that the certificate and key match.
    assert got_cert == wanted.get_certificate()
    assert private_keys_equal(got_key, wanted.get_private_key())


def test_write_pem_files_with_password(tmp_path):
    wanted = Credential().subject("CN=joe").generate()
    wanted.write_certificates_as_pem(tmp_path / "joe.pem")
    wanted.write_private_key_as_pem(tmp_path / "joe-key.pem", password="secret")

    # Load certificate and key from files.
    got_cert = x509.load_pem_x509_certificate((tmp_path / "joe.pem").read_bytes())
    got_key = serialization.load_pem_private_key((tmp_path / "joe-key.pem").read_bytes(), b"secret")

    # Check that the certificate and key match.
    assert got_cert == wanted.get_certificate()
    assert private_keys_equal(got_key, wanted.get_private_key())


# Helpers


def key_must_be(cred, key_type, key_size):
    return isinstance(cred.get_private_key(), key_type) and cred.get_private_key().key_size == key_size


def private_keys_equal(key1, key2):
    return key1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) == key2.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
