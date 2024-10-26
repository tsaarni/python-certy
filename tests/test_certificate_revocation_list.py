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

from datetime import datetime, timezone
import pytest
from cryptography import x509

from certy import CertificateRevocationList, Credential


@pytest.fixture
def ca():
    return Credential().subject("CN=ca")


def test_add(ca):
    first_revoked = Credential().issuer(ca).subject("CN=first-revoked")
    second_revoked = Credential().issuer(ca).subject("CN=second-revoked")
    not_revoked = Credential().issuer(ca).subject("CN=not-revoked")
    crl = CertificateRevocationList().issuer(ca).add(first_revoked).add(second_revoked).get_as_der()

    got = x509.load_der_x509_crl(crl)
    assert got is not None
    assert got.get_revoked_certificate_by_serial_number(first_revoked.get_certificate().serial_number) is not None
    assert got.get_revoked_certificate_by_serial_number(second_revoked.get_certificate().serial_number) is not None
    assert got.get_revoked_certificate_by_serial_number(not_revoked.get_certificate().serial_number) is None


def test_this_update(ca):
    crl = CertificateRevocationList().issuer(ca).this_update(datetime(2023, 10, 31, 9, 0))
    got = x509.load_der_x509_crl(crl.get_as_der())
    assert got is not None
    assert got.last_update_utc == datetime(2023, 10, 31, 9, 0, tzinfo=timezone.utc)


def test_next_update(ca):
    crl = CertificateRevocationList().issuer(ca).this_update(datetime(2023, 10, 31, 9, 0)).next_update(datetime(2024, 10, 31, 9, 0))
    got = x509.load_der_x509_crl(crl.get_as_der())
    assert got is not None
    assert got.next_update_utc == datetime(2024, 10, 31, 9, 0, tzinfo=timezone.utc)


def test_issuer(ca):
    crl = CertificateRevocationList().issuer(ca)
    got = x509.load_der_x509_crl(crl.get_as_der())
    assert got is not None
    assert got.issuer == ca.get_certificate().subject


def test_signature(ca):
    crl = CertificateRevocationList().issuer(ca)
    got = crl.get_as_der()
    assert got is not None
    assert x509.load_der_x509_crl(got).is_signature_valid(ca.get_private_key().public_key())


def test_get_as_pem(ca):
    revoked = Credential().issuer(ca).subject("CN=revoked")
    crl = CertificateRevocationList().issuer(ca).add(revoked)
    got = crl.get_as_pem()
    assert got is not None
    assert (
        x509.load_pem_x509_crl(got).get_revoked_certificate_by_serial_number(revoked.get_certificate().serial_number)
        is not None
    )


def test_get_as_der(ca):
    revoked = Credential().issuer(ca).subject("CN=revoked")
    crl = CertificateRevocationList().add(revoked)
    got = crl.get_as_der()
    assert got is not None
    assert (
        x509.load_der_x509_crl(got).get_revoked_certificate_by_serial_number(revoked.get_certificate().serial_number)
        is not None
    )


def test_write_pem(ca, tmp_path):
    revoked = Credential().issuer(ca).subject("CN=revoked")
    crl = CertificateRevocationList().issuer(ca).add(revoked)
    crl.write_pem(tmp_path / "crl.pem")
    got = x509.load_pem_x509_crl((tmp_path / "crl.pem").read_bytes())
    assert got is not None
    assert got.get_revoked_certificate_by_serial_number(revoked.get_certificate().serial_number) is not None


def test_write_der(ca, tmp_path):
    revoked = Credential().issuer(ca).subject("CN=revoked")
    crl = CertificateRevocationList().issuer(ca).add(revoked)
    crl.write_der(tmp_path / "crl.der")
    got = x509.load_der_x509_crl((tmp_path / "crl.der").read_bytes())
    assert got is not None
    assert got.get_revoked_certificate_by_serial_number(revoked.get_certificate().serial_number) is not None


def test_cannot_determine_issuer():
    with pytest.raises(ValueError):
        CertificateRevocationList().get_as_pem()


def test_cannot_revoke_self_signed(ca):
    with pytest.raises(ValueError):
        CertificateRevocationList().add(ca).get_as_pem()


def test_mismatched_issuer(ca):
    with pytest.raises(ValueError):
        CertificateRevocationList().issuer(ca).add(Credential().subject("CN=not-issued-by-ca")).get_as_pem()
