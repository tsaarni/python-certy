Welcome to certy's documentation!
=================================

Certy provides a simple API for creating X509 certificates on demand when running unit tests. No more storing test certificates and private keys in the repository!

Python-certy is a version of similar tool for command line and Golang called `certyaml`_ and `java-certy`_ for Java.

Following example creates a CA certificate and a server certificate signed by the CA.
The server certificate is valid for host ``app.127.0.0.1.nip.io``.

.. code-block:: python
   :linenos:

   from certy import Credential

   ca = Credential().subject("CN=ca")
   ca.write_certificates_as_pem("ca.pem")

   cred = Credential().subject("CN=server")
                      .issuer(ca)
                      .subject_alt_names("DNS:app.127.0.0.1.nip.io")
   cred.write_certificates_as_pem("cert.pem")
   cred.write_private_key_as_pem("key.pem")


Installation
============

You can install certy from PyPI:

.. code-block:: bash

   pip install certy


API Reference
=============

.. automodule:: certy
   :members:
   :undoc-members:


.. _certyaml: https://github.com/tsaarni/certyaml
.. _java-certy: https://github.com/tsaarni/java-certy/


Bugs and feature requests
=========================

You can report bugs and request new features in the GitHub issue tracker at https://github.com/tsaarni/python-certy