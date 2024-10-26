from datetime import datetime

import pytest

from certy import Credential, ExtendedKeyUsage, KeyType, KeyUsage


def test_invalid_subject():
    with pytest.raises(ValueError):
        Credential().subject("not a valid subject").generate()
    with pytest.raises(ValueError):
        Credential().subject(123)


def test_empty_subject():
    with pytest.raises(ValueError):
        Credential().generate()


def test_invalid_subject_alternative_names():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").subject_alt_names(
            "DNS:www.example.com", "not a valid subject alternative name"
        ).generate()


def test_invalid_key_type():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_type("not a valid key type")


def test_invalid_key_size():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_size(123).generate()
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_type(KeyType.EC).key_size(123)
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_type(KeyType.RSA).key_size(123)
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_size("not a valid key size")
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_type(KeyType.ED25519).key_size(123)


def test_invalid_ca():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").ca("not a valid ca")


def test_invalid_issuer():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").issuer("not a valid issuer")


def test_invalid_expires():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").expires("not a valid expires")


def test_invalid_not_before():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").not_before("not a valid not_before")


def test_invalid_not_after():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").not_after("not a valid not_after")


def test_invalid_serial():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").serial("not a valid serial")


def test_invalid_key_usage():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_usages("not a valid key usage")
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").key_usages(KeyUsage.DIGITAL_SIGNATURE, "not a valid key usage")


def test_invalid_ext_key_usage():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").ext_key_usages("not a valid extended key usage")
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").ext_key_usages(ExtendedKeyUsage.SERVER_AUTH, "not a valid extended key usage")


def test_not_before_later_than_not_after():
    with pytest.raises(ValueError):
        Credential().subject("CN=joe").not_before(datetime(2023, 1, 1)).not_after(datetime(2022, 1, 1)).generate()
