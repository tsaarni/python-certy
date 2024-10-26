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

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from certy import Credential


class CertificateRevocationList(object):
    """CertificateRevocationList is a builder for X.509 CRLs."""

    def __init__(
        self,
        issuer: Credential | None = None,
        revoked_certificates: list[Credential] | None = None,
        this_update: datetime | None = None,
        next_update: datetime | None = None,
    ):
        self._issuer = issuer
        self._revoked_certificates = revoked_certificates or []
        self._this_update = this_update
        self._next_update = next_update

        # Generated attributes
        self._crl: x509.CertificateRevocationList | None = None

    def __repr__(self) -> str:
        issuer_name = self._issuer._subject if self._issuer else None
        subject_names = [revoked._subject for revoked in self._revoked_certificates]
        return f"CertificateRevocationList(issuer={issuer_name!r}, revoked_certificates={subject_names!r}, this_update={self._this_update!r}, next_update={self._next_update!r})"

    # Setter methods

    def issuer(self, issuer: Credential) -> CertificateRevocationList:
        """Set the issuer of the CRL.

        If not called, the issuer will be inferred from the first certificate added to the CRL by calling :meth:`add`.

        :param issuer: The issuer of the CRL.
        :type issuer: Credential
        :return: self
        :rtype: CertificateRevocationList
        """
        self._issuer = issuer
        return self

    def this_update(self, this_update: datetime) -> CertificateRevocationList:
        """Set the ``thisUpdate`` field of the CRL.

        If not called, the ``thisUpdate`` field will be set to the current time.

        :param this_update: The ``thisUpdate`` field of the CRL.
        :type this_update: datetime
        :return: self
        :rtype: CertificateRevocationList
        """
        self._this_update = this_update
        return self

    def next_update(self, next_update: datetime) -> CertificateRevocationList:
        """Set the ``nextUpdate`` field of the CRL.

        If not called, the ``nextUpdate`` field will be set to ``thisUpdate`` plus 7 days.

        :param next_update: The nextUpdate field of the CRL.
        :type next_update: datetime
        :return: self
        :rtype: CertificateRevocationList
        """
        self._next_update = next_update
        return self

    def add(self, certificate: Credential) -> CertificateRevocationList:
        """Add a certificate to the CRL.

        All certificates added to the CRL must have the same issuer.

        :param certificate: The certificate to add to the CRL.
        :type certificate: Credential
        :return: self
        :rtype: CertificateRevocationList
        """

        if self._issuer and certificate._issuer != self._issuer:
            raise ValueError("issuer mismatch")
        if self._revoked_certificates and certificate._issuer != self._revoked_certificates[0]._issuer:
            raise ValueError("issuer mismatch")

        self._revoked_certificates.append(certificate)
        return self

    # Builder methods

    def generate(self) -> CertificateRevocationList:
        """Generate the CRL.

        This method will (re)generate the CRL. It will be called automatically if the CRL is not yet generated when
        :meth:`get_as_pem`, :meth:`get_as_der`, :meth:`write_pem` or :meth:`write_der` is called.

        :return: self
        :rtype: CertificateRevocationList
        """
        if not self._issuer:
            if not self._revoked_certificates:
                raise ValueError("issuer not known: either set issuer or add certificates to the CRL")
            if self._revoked_certificates[0]._issuer is None:
                raise ValueError("cannot determine issuer from first certificate in CRL")
            self._issuer = self._revoked_certificates[0]._issuer

        # Ensure that the issuer has a key pair.
        self._issuer._ensure_generated()

        effective_revocation_time = datetime.now(timezone.utc)
        if self._this_update:
            effective_revocation_time = self._this_update

        effective_expiry_time = effective_revocation_time + timedelta(days=7)
        if self._next_update:
            effective_expiry_time = self._next_update

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._issuer._certificate.subject)  # type: ignore
            .last_update(effective_revocation_time)
            .next_update(effective_expiry_time)
        )

        for certificate in self._revoked_certificates:
            certificate._ensure_generated()
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(certificate._certificate.serial_number)  # type: ignore
                .revocation_date(effective_revocation_time)
                .build()
            )

        self._crl = builder.sign(
            private_key=self._issuer._private_key,  # type: ignore
            algorithm=self._issuer._certificate.signature_hash_algorithm,  # type: ignore
        )

        return self

    def get_as_pem(self) -> bytes:
        """Get the CRL as PEM.

        :return: The CRL as PEM.
        :rtype: bytes
        """
        self._ensure_generated()
        return self._crl.public_bytes(encoding=serialization.Encoding.PEM)  # type: ignore

    def get_as_der(self) -> bytes:
        """Get the CRL as DER.

        :return: The CRL as DER.
        :rtype: bytes
        """
        self._ensure_generated()
        return self._crl.public_bytes(encoding=serialization.Encoding.DER)  # type: ignore

    def write_pem(self, filename: str) -> CertificateRevocationList:
        """Write the CRL as PEM to a file.

        :param filename: The filename to write the CRL to.
        :type filename: str
        :return: self
        :rtype: CertificateRevocationList
        """
        self._ensure_generated()
        with open(filename, "wb") as f:
            f.write(self.get_as_pem())
        return self

    def write_der(self, filename: str) -> CertificateRevocationList:
        """Write the CRL as DER to a file.

        :param filename: The filename to write the CRL to.
        :type filename: str
        :return: self
        :rtype: CertificateRevocationList
        """
        self._ensure_generated()
        with open(filename, "wb") as f:
            f.write(self.get_as_der())
        return self

    # Helper methods

    def _ensure_generated(self) -> CertificateRevocationList:
        """Ensure that the CRL has been generated."""
        if not self._crl:
            self.generate()
        return self
