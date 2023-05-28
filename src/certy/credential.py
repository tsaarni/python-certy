from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


class Credential(object):
    def __init__(self):
        self._key_type: KeyType | None = None
        self._key_size: int | None = None
        self._private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None
        self._expires: timedelta | None = None
        self._not_before: datetime | None = None
        self._not_after: datetime | None = None
        self._subject: x509.Name | None = None
        self._subject_alt_names: x509.GeneralNames | None = None
        self._issuer: Credential | None = None
        self._is_ca: bool | None = None
        self._key_usages: List[KeyUsage] | None = None
        self._ext_key_usages: List[ExtendedKeyUsage] | None = None
        self._serial: int | None = None
        self._certificate: x509.Certificate | None = None

    def __repr__(self):
        return "<Credential: %s>" % self

    def ca(self, ca: bool = True) -> Credential:
        self._is_ca = ca
        return self

    def subject(self, subject: str) -> Credential:
        self._subject = x509.Name.from_rfc4514_string(subject)
        return self

    def subject_alt_name(self, subject_alt_names: str | List[str]) -> Credential:
        if isinstance(subject_alt_names, str):
            subject_alt_names = [subject_alt_names]

        self._subject_alt_names = as_general_names(subject_alt_names)
        return self

    def issuer(self, issuer: Credential) -> Credential:
        self._issuer = issuer
        return self

    def key_type(self, key_type: KeyType) -> Credential:
        self._key_type = key_type
        return self

    def key_size(self, key_size: int) -> Credential:
        self._key_size = key_size
        return self

    def expires(self, expires: timedelta) -> Credential:
        self._expires = expires
        return self

    def not_before(self, not_before: datetime) -> Credential:
        self._not_before = not_before
        return self

    def not_after(self, not_after: datetime) -> Credential:
        self._not_after = not_after
        return self

    def serial(self, serial: int) -> Credential:
        self._serial = serial
        return self

    def key_usages(self, key_usages: List[KeyUsage]) -> Credential:
        self._key_usages = key_usages
        return self

    def ext_key_usages(self, ext_key_usages: List[ExtendedKeyUsage]) -> Credential:
        self._ext_key_usages = ext_key_usages
        return self

    def _ensure_generated(self) -> Credential:
        if self._certificate is None:
            self.generate()
        return self

    def generate(self) -> Credential:
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
            else:
                raise ValueError("Unknown key type")

        if self._expires is None and self._not_after is None:
            self._expires = timedelta(days=365)

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

        effective_not_before = self._not_before
        effective_not_after = self._not_after
        if effective_not_before is None:
            effective_not_before = datetime.utcnow()
        if effective_not_after is None and self._expires is not None:
            effective_not_after = effective_not_before + self._expires
        elif effective_not_after is not None:
            if effective_not_after < effective_not_before:
                raise ValueError("not_after must be after not_before")
        else:
            raise ValueError("Either expires or not_after must be set")

        if self._issuer is not None:
            assert self._issuer._subject is not None

        self._private_key = generate_new_key(self._key_type, self._key_size)

        builder = (
            x509.CertificateBuilder()
            .subject_name(self._subject)
            .issuer_name(effective_issuer._subject)  # type: ignore
            .not_valid_before(effective_not_before)
            .not_valid_after(effective_not_after)
            .serial_number(self._serial)
            .public_key(self._private_key.public_key())
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=self._is_ca, path_length=None), critical=True
        )

        if self._subject_alt_names is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(self._subject_alt_names), critical=False
            )

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

        self._certificate = builder.sign(
            effective_issuer._private_key,  # type: ignore
            preferred_signature_hash_algorithm(effective_issuer._key_type, effective_issuer._key_size),  # type: ignore
        )
        return self

    def _get_chain(self) -> List[x509.Certificate]:
        chain = [self._certificate]
        parent = self._issuer
        while parent is not None and parent._issuer is not None:
            chain.append(parent._certificate)
            parent = parent._issuer
        return chain  # type: ignore

    def get_certificate(self) -> x509.Certificate:
        self._ensure_generated()
        return self._certificate

    def get_certificates(self) -> List[x509.Certificate]:
        self._ensure_generated()
        return self._get_chain()

    def get_certificate_as_pem(self) -> bytes:
        self._ensure_generated()
        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)

    def get_certificates_as_pem(self) -> bytes:
        self._ensure_generated()
        return b"".join(
            cert.public_bytes(encoding=serialization.Encoding.PEM)
            for cert in self._get_chain()
        )

    def get_private_key(self) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        self._ensure_generated()
        return self._private_key

    def get_private_key_as_pem(self) -> bytes:
        self._ensure_generated()
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def write_certificate_as_pem(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.get_certificate_as_pem())

    def write_certificates_as_pem(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.get_certificates_as_pem())

    def write_private_key_as_pem(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.get_private_key_as_pem())


class KeyType(Enum):
    RSA = 1
    EC = 2


class KeyUsage(Enum):
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
    SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
    CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
    CODE_SIGNING = ExtendedKeyUsageOID.CODE_SIGNING
    EMAIL_PROTECTION = ExtendedKeyUsageOID.EMAIL_PROTECTION
    TIME_STAMPING = ExtendedKeyUsageOID.TIME_STAMPING
    OCSP_SIGNING = ExtendedKeyUsageOID.OCSP_SIGNING


def generate_new_key(
    key_type: KeyType, key_size: int
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
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
            raise ValueError("Invalid key size")

        return ec.generate_private_key(curve)

    raise ValueError("Invalid key type")


def as_general_names(names: List[str]) -> x509.GeneralNames:
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
            raise ValueError("Invalid name, must start with DNS:, IP: or URI:")
    return x509.GeneralNames(general_names)


def preferred_signature_hash_algorithm(
    key_type: KeyType, key_size: int
) -> hashes.HashAlgorithm:
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
            raise ValueError("Invalid key size")
    else:
        raise ValueError("Invalid key type")
