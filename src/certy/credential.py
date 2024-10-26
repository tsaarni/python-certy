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

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID


class KeyType(Enum):
    """Key types are used with :meth:`Credential.key_type` to specify the type of key to generate."""

    EC = 1
    """Elliptic curve key (default)."""
    RSA = 2
    """RSA key."""
    ED25519 = 3
    """Ed25519 key."""


class KeyUsage(Enum):
    """Key usages are used with :meth:`Credential.key_usage` to specify the key usages for the certificate."""

    DIGITAL_SIGNATURE = "digital_signature"
    NON_REPUDIATION = "content_commitment"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


class ExtendedKeyUsage(Enum):
    """Extended key usages are used with :meth:`Credential.ext_key_usages` to specify the extended key usages for the certificate."""

    SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
    """Certificate can be used as TLS server certificate."""
    CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
    """Certificate can be used as TLS client certificate."""
    CODE_SIGNING = ExtendedKeyUsageOID.CODE_SIGNING
    """Certificate can be used for code signing."""
    EMAIL_PROTECTION = ExtendedKeyUsageOID.EMAIL_PROTECTION
    """Certificate can be used for email protection (signing, encryption, key agreement)."""
    TIME_STAMPING = ExtendedKeyUsageOID.TIME_STAMPING
    """Certificate can be used to bind the hash of an object to a time from a trusted time source."""
    OCSP_SIGNING = ExtendedKeyUsageOID.OCSP_SIGNING
    """Private key associated to certificate can be used to sign OCSP response."""


class Credential(object):
    """Credential representing a certificate and associated private key"""

    def __init__(
        self,
        subject: x509.Name | None = None,
        subject_alt_names: x509.GeneralNames | None = None,
        key_type: KeyType | None = None,
        key_size: int | None = None,
        expires: timedelta | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        issuer: Credential | None = None,
        is_ca: bool | None = None,
        key_usages: list[KeyUsage] | None = None,
        ext_key_usages: list[ExtendedKeyUsage] | None = None,
        serial: int | None = None,
        crl_distribution_point_uri: str | None = None,
    ):
        self._subject = subject
        self._subject_alt_names = subject_alt_names
        self._key_type = key_type
        self._key_size = key_size
        self._expires = expires
        self._not_before = not_before
        self._not_after = not_after
        self._issuer = issuer
        self._is_ca = is_ca
        self._key_usages = key_usages
        self._ext_key_usages = ext_key_usages
        self._serial = serial
        self._crl_distribution_point_uri = crl_distribution_point_uri

        # Generated attributes
        self._private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | None = None
        self._certificate: x509.Certificate | None = None

    def __repr__(self):
        return f"Credential(subject={self._subject!r}, key_type={self._key_type!r}, key_size={self._key_size!r}, expires={self._expires!r}, not_before={self._not_before!r}, not_after={self._not_after!r}, issuer={self._issuer!r}, is_ca={self._is_ca!r}, key_usages={self._key_usages!r}, ext_key_usages={self._ext_key_usages!r}, serial={self._serial!r}, crl_distribution_point_uri={self._crl_distribution_point_uri!r})"

    # Setter methods

    def ca(self, ca: bool = True) -> Credential:
        """Set whether this credential is a CA or not.

        If CA is set to :const:`True`, the key usage :const:`KeyUsage.KEY_CERT_SIGN` and :const:`KeyUsage.CRL_SIGN` are set
        to the certificate, and the basic constraints extension is included with ``ca`` field set to :const:`True``.

        If not called, :const:`True` is used for credentials that are self-signed, :const:`False` for credentials that are not.

        :param ca: Whether this credential is a CA or not.
        :type ca: bool
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(ca, bool):
            raise ValueError("CA must be a boolean")
        self._is_ca = ca
        return self

    def subject(self, subject: str) -> Credential:
        """Set the subject name of this credential.

        :param subject: The subject name of this credential. Must be a valid RFC4514 string,
            for example ``CN=example.com``.
        :type subject: str
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(subject, str):
            raise ValueError("Subject must be a string")
        self._subject = x509.Name.from_rfc4514_string(subject)
        return self

    def subject_alt_names(self, *subject_alt_names: str) -> Credential:
        """Set the subject alternative names of this credential.

        If not called, the subject alternative names extension is not included in the certificate.

        :param subject_alt_names: The subject alternative name or names of this credential.
            Must be one of the following:
            DNS name for example ``DNS:example.com``,
            IP address ``IP:1.2.3.4``,
            or URI ``URI:https://example.com``.
        :type subject_alt_names: tuple[str]
        :return: This credential instance.
        :rtype: Credential
        """
        self._subject_alt_names = _as_general_names(list(subject_alt_names))
        return self

    def issuer(self, issuer: Credential) -> Credential:
        """Set the issuer of this credential.

        If not called, the issuer is set to the same value as the subject and the certificate is self-signed.

        :param issuer: The issuer of this credential.
        :type issuer: Credential
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(issuer, Credential):
            raise ValueError("Issuer must be a certy.Credential instance")
        self._issuer = issuer
        return self

    def key_type(self, key_type: KeyType) -> Credential:
        """Set the key type of this credential.

        If not called, the key type will be :const:`KeyType.EC`.

        :param key_type: The key type of this credential. Must be :const:`KeyType.EC`, :const:`KeyType.RSA` or :const:`KeyType.ED25519`.
        :type key_type: KeyType
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(key_type, KeyType):
            raise ValueError("Key type must be certy.KeyType.EC, certy.KeyType.RSA or certy.KeyType.ED25519")
        self._key_type = key_type
        return self

    def key_size(self, key_size: int) -> Credential:
        """Set the key size of this credential.

        If not called, the key size is ``256`` for :const:`KeyType.EC` and ``2048`` for :const:`KeyType.RSA`.
        :const:`KeyType.ED25519` has a fixed key size of ``256``.

        :param key_size: The key size of this credential. Valid values depend on the key type.
            For EC keys, valid values are 256, 384, and 521.
            For RSA keys, valid values are 1024, 2048, and 4096.
            For ED25519 keys, valid value is 256.
        :type key_size: int
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(key_size, int):
            raise ValueError("Key size must be an integer")
        if self._key_type == KeyType.EC and key_size not in (256, 384, 521):
            raise ValueError("EC key size must be 256, 384, or 521")
        elif self._key_type == KeyType.RSA and key_size < 1024:
            raise ValueError("RSA key size must be at least 1024")
        elif self._key_type == KeyType.ED25519 and key_size != 256:
            raise ValueError("ED25519 key size must be 256")
        self._key_size = key_size
        return self

    def expires(self, expires: timedelta) -> Credential:
        """Set the expiration time of this credential.

        The value is used to calculate the ``notAfter`` time for the certificate.
        If not called, the certificate will expire 365 days from ``notBefore``, unless overridden by
        calling :meth:`not_after`.

        :param expires: The expiration time of this credential.
        :type expires: datetime.timedelta
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(expires, timedelta):
            raise ValueError("Expires must be a datetime.timedelta instance")
        self._expires = expires
        return self

    def not_before(self, not_before: datetime) -> Credential:
        """Set the not before time of this credential.

        If not called, current time is used.

        :param not_before: The not before time of this credential.
        :type not_before: datetime.datetime
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(not_before, datetime):
            raise ValueError("Not before must be a datetime.datetime instance")
        self._not_before = not_before
        return self

    def not_after(self, not_after: datetime) -> Credential:
        """Set the not after time of this credential.

        If not called, the not after time will be set to time given by :meth:`not_before`
        plus the expiration time set by :meth:`expires`.

        :param not_after: The not after time of this credential.
        :type not_after: datetime.datetime
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(not_after, datetime):
            raise ValueError("Not after must be a datetime.datetime instance")
        self._not_after = not_after
        return self

    def serial(self, serial: int) -> Credential:
        """Set the serial number of this credential.

        If not called, the serial number is set to a random value.

        :param serial: The serial number of this credential.
        :type serial: int
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(serial, int):
            raise ValueError("Serial must be an integer")
        self._serial = serial
        return self

    def key_usages(self, *key_usages: KeyUsage) -> Credential:
        """Set the key usages of this credential.

        If not called, the key usages :const:`KeyUsage.DIGITAL_SIGNATURE` and :const:`KeyUsage.KEY_ENCIPHERMENT` are set
        to end-entity certificates (:meth:`ca` is :const:`False`), and :const:`KeyUsage.KEY_CERT_SIGN` and
        :const:`KeyUsage.CRL_SIGN` are set to CA certificates (:meth:`ca` is :const:`True`).

        :param key_usages: The key usages of this credential. One or more of :const:`KeyUsage`.
        :type key_usages: tuple[certy.KeyUsage]
        :return: This credential instance.
        :rtype: Credential
        """
        for key_usage in key_usages:
            if not isinstance(key_usage, KeyUsage):
                raise ValueError("Key usages must be a list of certy.KeyUsage")
        self._key_usages = key_usages
        return self

    def ext_key_usages(self, *ext_key_usages: ExtendedKeyUsage) -> Credential:
        """Set the extended key usages of this credential.

        If not called, extended key usages extension is not be included in the certificate.

        :param ext_key_usages: The extended key usages of this credential. One or more of :const:`ExtendedKeyUsage`.
        :type ext_key_usages: tuple[ExtendedKeyUsage]
        :return: This credential instance.
        :rtype: Credential
        """
        for ext_key_usage in ext_key_usages:
            if not isinstance(ext_key_usage, ExtendedKeyUsage):
                raise ValueError("Extended key usages must be a list of certy.ExtendedKeyUsage")
        self._ext_key_usages = ext_key_usages
        return self

    def crl_distribution_point_uri(self, uri: str) -> Credential:
        """Set the CRL distribution point URI of this credential.

        If not called, the CRL distribution point extension is not included in the certificate.

        :param uri: The URI of the CRL distribution point.
        :type uri: str
        :return: This credential instance.
        :rtype: Credential
        """
        if not isinstance(uri, str):
            raise ValueError("URI must be a string")
        self._crl_distribution_point_uri = uri
        return self

    # Builder methods

    def generate(self) -> Credential:
        """Generate the credential.
        This method will (re)generate the private key and the certificate.

        :return: This credential instance.
        :rtype: Credential
        """
        if self._subject is None:
            raise ValueError("Subject must be set")

        effective_issuer = None
        if self._issuer is None:
            effective_issuer = self  # self-signed certificate
        else:
            # Recursively generate the issuer(s) first.
            effective_issuer = self._issuer._ensure_generated()

        if self._key_type is None:
            self._key_type = KeyType.EC

        if self._key_size is None:
            if self._key_type == KeyType.EC:
                self._key_size = 256
            elif self._key_type == KeyType.RSA:
                self._key_size = 2048
            elif self._key_type == KeyType.ED25519:
                self._key_size = 256
            else:
                raise ValueError("Unknown key type")

        if self._is_ca is None:
            no_explicit_issuer = self._issuer is None
            self._is_ca = no_explicit_issuer

        if self._key_usages is None:
            if self._is_ca:
                self._key_usages = [KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN]
            else:
                self._key_usages = [
                    KeyUsage.DIGITAL_SIGNATURE,
                    KeyUsage.KEY_ENCIPHERMENT,
                ]

        if self._serial is None:
            self._serial = x509.random_serial_number()

        if self._expires is None and self._not_after is None:
            self._expires = timedelta(days=365)

        effective_not_before = self._not_before
        effective_not_after = self._not_after
        if effective_not_before is None:
            effective_not_before = datetime.now(timezone.utc)
        if effective_not_after is None and self._expires is not None:
            effective_not_after = effective_not_before + self._expires
        elif effective_not_after is not None:
            if effective_not_after < effective_not_before:
                raise ValueError("not_after must be after not_before")
        else:
            raise ValueError("Either expires or not_after must be set")

        if self._issuer is not None:
            assert self._issuer._subject is not None

        self._private_key = _generate_new_key(self._key_type, self._key_size)

        builder = (
            x509.CertificateBuilder()
            .subject_name(self._subject)
            .issuer_name(effective_issuer._subject)  # type: ignore
            .not_valid_before(effective_not_before)
            .not_valid_after(effective_not_after)
            .serial_number(self._serial)
            .public_key(self._private_key.public_key())
        )

        builder = builder.add_extension(x509.BasicConstraints(ca=self._is_ca, path_length=None), critical=True)

        if self._subject_alt_names is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName(self._subject_alt_names), critical=False)

        if self._key_usages is not None:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=KeyUsage.DIGITAL_SIGNATURE in self._key_usages,
                    content_commitment=KeyUsage.NON_REPUDIATION in self._key_usages,
                    key_encipherment=KeyUsage.KEY_ENCIPHERMENT in self._key_usages,
                    data_encipherment=KeyUsage.DATA_ENCIPHERMENT in self._key_usages,
                    key_agreement=KeyUsage.KEY_AGREEMENT in self._key_usages,
                    key_cert_sign=KeyUsage.KEY_CERT_SIGN in self._key_usages,
                    crl_sign=KeyUsage.CRL_SIGN in self._key_usages,
                    encipher_only=KeyUsage.ENCIPHER_ONLY in self._key_usages,
                    decipher_only=KeyUsage.DECIPHER_ONLY in self._key_usages,
                ),
                critical=True,
            )

        if self._ext_key_usages is not None:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([usage.value for usage in self._ext_key_usages]),
                critical=False,
            )

        if self._crl_distribution_point_uri is not None:
            builder = builder.add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(self._crl_distribution_point_uri)],
                            relative_name=None,
                            crl_issuer=None,
                            reasons=None,
                        )
                    ]
                ),
                critical=False,
            )

        self._certificate = builder.sign(
            effective_issuer._private_key,  # type: ignore
            _preferred_signature_hash_algorithm(effective_issuer._key_type, effective_issuer._key_size),  # type: ignore
        )
        return self

    def get_certificate(self) -> x509.Certificate:
        """Get the certificate.

        If the certificate has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :return: The certificate.
        :rtype: cryptography.x509.Certificate
        """
        self._ensure_generated()
        return self._certificate  # type: ignore

    def get_certificates(self) -> list[x509.Certificate]:
        """Get the certificate chain including the certificate itself and its issuers.
        It will not include the root CA.

        If the certificate has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :return: The certificate chain.
        :rtype: list[cryptography.x509.Certificate]
        """
        self._ensure_generated()
        return self._get_chain()

    def get_certificate_as_pem(self) -> bytes:
        """Get the certificate in PEM format.

        If the certificate has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :return: The certificate in PEM format.
        :rtype: bytes
        """
        self._ensure_generated()
        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)  # type: ignore

    def get_certificates_as_pem(self) -> bytes:
        """Get the certificate chain in PEM format.
        The PEM bundle includes the certificate itself and its issuers, but not the root CA.

        If the certificate has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :return: The certificate chain in PEM format.
        :rtype: bytes
        """
        self._ensure_generated()
        return b"".join(cert.public_bytes(encoding=serialization.Encoding.PEM) for cert in self._get_chain())

    def get_private_key(self) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        """Get the private key.

        If the private key has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :return: The private key.
        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey | cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
        """
        self._ensure_generated()
        return self._private_key  # type: ignore

    def get_private_key_as_pem(self, password: str | None = None) -> bytes:
        """Get the private key in PKCS#8 PEM format.

        If the private key has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :param password: The password to encrypt the private key with. If not set, the private key is not encrypted.
        :return: The private key in PKCS#8 PEM format.
        :rtype: bytes
        """
        self._ensure_generated()

        encryption_algorithm: serialization.KeySerializationEncryption = serialization.NoEncryption()
        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode("utf-8"))

        return self._private_key.private_bytes(  # type: ignore
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

    def write_certificate_as_pem(self, path: str) -> Credential:
        """Write the certificate in PEM format to a file.

        If the certificate has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :param path: The path to the file.
        :type path: str
        :return: This credential instance.
        :rtype: Credential
        """
        with open(path, "wb") as f:
            f.write(self.get_certificate_as_pem())
        return self

    def write_certificates_as_pem(self, path: str) -> Credential:
        """Write the certificate chain in PEM format to a file.
        The PEM bundle includes the certificate itself and its issuers, but not the root CA.

        If the certificate has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :param path: The path to the file.
        :type path: str
        :return: This credential instance.
        :rtype: Credential
        """
        with open(path, "wb") as f:
            f.write(self.get_certificates_as_pem())
        return self

    def write_private_key_as_pem(self, path: str, password: str | None = None) -> Credential:
        """Write the private key in PKCS#8 PEM format to a file.

        If the private key has not been generated yet by calling :meth:`generate`, it is generated automatically.

        :param path: The path to the file.
        :type path: str
        :param password: The password to encrypt the private key with. If not set, the private key is not encrypted.
        :type password: str | None
        :return: This credential instance.
        :rtype: Credential
        """
        with open(path, "wb") as f:
            f.write(self.get_private_key_as_pem(password))
        return self

    # Helper methods

    def _ensure_generated(self) -> Credential:
        if self._certificate is None:
            self.generate()
        return self

    def _get_chain(self) -> list[x509.Certificate]:
        chain = [self._certificate]
        parent = self._issuer
        while parent is not None and parent._issuer is not None:
            chain.append(parent._certificate)
            parent = parent._issuer
        return chain  # type: ignore


# Helper functions


def _generate_new_key(key_type: KeyType, key_size: int) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey:
    if key_type == KeyType.RSA:
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == KeyType.EC:
        curve = None
        if key_size == 224 or key_size == 256:
            curve = ec.SECP256R1()
        elif key_size == 384:
            curve = ec.SECP384R1()
        elif key_size == 521:
            curve = ec.SECP521R1()
        else:
            raise ValueError(f"Invalid key size: {key_size}")

        return ec.generate_private_key(curve)
    elif key_type == KeyType.ED25519:
        return ed25519.Ed25519PrivateKey.generate()

    raise ValueError(f"Invalid key type: {key_type}")


def _as_general_names(names: list[str]) -> x509.GeneralNames:
    general_names = []
    for name in names:
        if name.startswith("DNS:"):
            general_names.append(x509.DNSName(name[4:]))
        elif name.startswith("IP:"):
            ip_address = ipaddress.ip_address(name[3:])
            general_names.append(x509.IPAddress(ip_address))
        elif name.startswith("URI:"):
            general_names.append(x509.UniformResourceIdentifier(name[4:]))
        else:
            raise ValueError(f"Invalid name '{name}', must start with DNS:, IP: or URI:")
    return x509.GeneralNames(general_names)


def _preferred_signature_hash_algorithm(key_type: KeyType, key_size: int) -> hashes.HashAlgorithm | None:
    if key_type == KeyType.RSA:
        return hashes.SHA256()
    elif key_type == KeyType.EC:
        if key_size == 224 or key_size == 256:
            return hashes.SHA256()
        elif key_size == 384:
            return hashes.SHA384()
        elif key_size == 521:
            return hashes.SHA512()
        else:
            raise ValueError(f"Invalid key size: {key_size}")
    elif key_type == KeyType.ED25519:
        return None
    else:
        raise ValueError(f"Invalid key type: {key_type!r}")
