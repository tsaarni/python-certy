Welcome to certy's documentation!
=================================

Certy provides a simple API for creating X509 certificates and certificate revocation lists on demand when running unit tests.
No more storing test certificates and private keys in the repository!

Python-certy is a version of similar tool for command line and Golang called `certyaml`_ and `java-certy`_ for Java.

Installation
============

Install certy from `pypi`_

.. code-block:: bash

   pip install certy


Examples
========

Basics: issuing certificates
----------------------------

Following example creates a CA certificate, a server certificate signed by the CA and writes them to files.

.. literalinclude:: ../examples/write-ca-and-server-cert.py
   :linenos:

Given defaults are typically OK, which makes simple use very simple:

* CA certificate will automatically include basic constrains extension with CA field set. It is recognized as CA, because ``ca.issuer()`` was not called.
* Server certificate is recognized as end-entity certificate, since it is signed by the CA - ``server.issuer(ca)`` was called.
* Key usage is set according to the certificate type: CA certificates are allowed to sign other certificates, end-entity certificates are allowed to be used for TLS server and client authentication.
* The ``validFrom`` and ``validTo`` fields are set to current time and one year in the future, respectively.
* ``EC`` key type of 256 bits is used.
* Serial number is randomly generated.

Complete example: HTTPS server and client
-----------------------------------------

Following example creates two PKI hierarchies:

* The server PKI hierarchy contains a root CA and intermediate CA. The server certificate is signed by the intermediate.
* The client PKI hierarchy contains just a root CA, which is used to sign the client certificate.

The HTTP server validates the client certificate against the client root CA and the client validates the server certificate against the server root CA.
The client also validates that the server hostname matches the certificate subject alternative name ``app.127.0.0.1.nip.io`` since that hostname is used to connect to the server.

.. literalinclude:: ../examples/https-server-and-client.py
   :linenos:

API Reference
=============

.. automodule:: certy
   :members:
   :undoc-members:


Contact information
===================

Please use the `github`_ project for reporting bugs, requesting features and submitting pull requests.


.. _certyaml: https://github.com/tsaarni/certyaml
.. _java-certy: https://github.com/tsaarni/java-certy/
.. _pypi: https://pypi.org/project/certy/
.. _github: https://github.com/tsaarni/python-certy
