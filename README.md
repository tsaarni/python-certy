# python-certy

![](https://github.com/tsaarni/python-certy/workflows/unit-tests/badge.svg)

## Description

Certy provides a simple API for creating X509 certificates on demand when running unit tests.
No more storing test certificates and private keys in the repository!

Python-certy is a version of similar tool for command line and Golang called [certyaml](https://github.com/tsaarni/certyaml) and [java-certy](https://github.com/tsaarni/java-certy/) for Java.

## Example

```python
from certy import Credential

ca = Credential().subject("CN=ca")
ca.write_certificates_as_pem("ca.pem")

cred = Credential().subject("CN=server").issuer(ca).subject_alt_names("DNS:app.127.0.0.1.nip.io")
cred.write_certificates_as_pem("cert.pem")
cred.write_private_key_as_pem("key.pem")
```
## Documentation

Documentation is available [here](https://tsaarni.github.io/python-certy/).

## Installation

You can install certy from PyPI:

```bash
pip install certy
```

## Development

Create virtual environment by running `python3 -m venv .venv`, then activate it `source .venv/bin/activate`.
Install dependencies by running `pip install -r dev-requirements.txt`.
Run tests with `pytest`.
To find out coverage of tests, execute `coverage run -m pytest` and then `coverage html`.
The coverage report is generated to `htmlcov/index.html`.

Run `make html` on `docs` directory to generate documentation.
Open `docs/_build/html/index.html` to view the generated documentation.