# functions to help testing and made available for use in autossl plugins

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime
import random
import string

from autossl import ssl, util

DATA_PATH = util.Path(__file__).parent.joinpath('data')


def create_ca_certificate(ca_name, key_size=4096, certificate_validity_days=365):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    key_id = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"%s" % ca_name)])

    now = datetime.datetime.utcnow()
    serial = x509.random_serial_number()
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(serial) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=certificate_validity_days)) \
        .add_extension(key_id, critical=False) \
        .add_extension(x509.AuthorityKeyIdentifier(key_id.digest,
                                                   [x509.DirectoryName(issuer)],
                                                   serial),
                       critical=False) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=3), critical=True) \
        .add_extension(x509.KeyUsage(digital_signature=True,
                                     content_commitment=False,
                                     key_encipherment=False,
                                     data_encipherment=False,
                                     key_agreement=False,
                                     key_cert_sign=True,
                                     crl_sign=True,
                                     encipher_only=False,
                                     decipher_only=False),
                       critical=True) \
        .sign(key, hashes.SHA256(), default_backend())

    cert = cert.public_bytes(serialization.Encoding.PEM)
    key = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption())
    return key, cert


def create_signed_certificate(csr_path, ca_crt_path=None, ca_key_path=None, certificate_validity_days=365):
    """Generate SSL certificate signed by Autossl CA
    :param csr_path: local path to CSR
    :type csr_path: pathlib.Path
    :param ca_crt_path: local path to CA certificate
    :type ca_crt_path: pathlib.Path
    :param ca_key_path: local path to CA private key
    :type ca_key_path: pathlib.Path
    :param certificate_validity_days: validity duration of certificate in days
    :type certificate_validity_days: int
    """
    # no CA specified => generate self signed cert from pkey generated on the fly
    if ca_crt_path is None or ca_key_path is None:
        ca_key, ca_crt = create_ca_certificate('autossl.com')
    else:
        ca_key = ca_key_path.read_bytes()
        ca_crt = ca_crt_path.read_bytes()
    csr = csr_path.read_bytes()
    return ssl.sign(csr, ca_key, ca_crt, certificate_validity_days)


def create_self_signed_certificate(crt_name, output_path, common_name, sans=None, certificate_validity_days=365):
    """Generate self signed SSL certificate
    :param crt_name: name of file generated (without extension)
    :type crt_name: str
    :param output_path: ouput directory to generate certificate
    :type output_path: pathlib.Path or str
    :param common_name: certificate common name
    :type common_name: str
    :param sans: certificate alternate names
    :type sans: list
    :param certificate_validity_days: validity duration of certificate in days
    :type certificate_validity_days: int
    """
    if not isinstance(output_path, util.Path):
        output_path = util.Path(str(output_path))
    key_path = output_path.joinpath(crt_name + '.key')
    key_content, csr_path = ssl.generate_csr(name=crt_name, common_name=common_name, sans=sans, output_path=output_path)
    crt_path = output_path.joinpath(crt_name + '.crt')
    crt_content = create_signed_certificate(
        csr_path=csr_path,
        certificate_validity_days=certificate_validity_days,
    )
    crt_path.write_bytes(crt_content)
    key_path.write_bytes(key_content)

    return key_path, crt_path


def create_autossl_signed_cert(ssl_blueprint, output_folder):
    """Create certificate signed by Autossl CA for specified blueprint and in specified location

    :param ssl_blueprint: SSL blueprint for which to generate certificate
    :type ssl_blueprint: ssl.SslBlueprint
    :param output_folder: local folder where to generate new key and signed certificate
    :type output_folder: pathlib.Path
    :return: 2-tuple(local path to private key, local path to signed certificate)
    :rtype: tuple(pathlib.Path, pathlib.Path)
    """
    if not isinstance(output_folder, util.Path):
        output_folder = util.Path(output_folder)

    ca_crt_path = DATA_PATH / 'ca' / 'autossl_ca.crt'
    ca_key_path = DATA_PATH / 'ca' / 'autossl_ca.key'

    crt_path = output_folder.joinpath(ssl_blueprint.name + '.crt')
    key_path = output_folder.joinpath(ssl_blueprint.name + '.key')

    # generate new CSR
    key_content, csr_path = ssl.generate_csr(
        name=ssl_blueprint.name,
        common_name=ssl_blueprint.certificate.common_name,
        sans=ssl_blueprint.certificate.sans,
        output_path=output_folder,
    )
    key_path.write_bytes(key_content)

    # sign a new certificate with the CA
    crt_content = create_signed_certificate(
        csr_path=csr_path,
        ca_crt_path=ca_crt_path,
        ca_key_path=ca_key_path,
    )
    crt_path.write_bytes(crt_content)

    return key_path, crt_path


def get_random_text(size=200):
    """
    :return: random printable characters, bytes encoded
    :rtype: byte
    """
    return ''.join(random.choice(string.printable) for _ in range(size)).encode('utf-8')


def get_random_ascii_string(size=20):
    return ''.join(random.choice(string.ascii_letters + '_') for _ in range(size))
