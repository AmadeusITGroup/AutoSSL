import collections
import shutil
import socket
import tempfile

import pytest

from autossl import exception, ssl, util
from autossl.server import local

from tests import util as tests_util


CertificateKeyPair = collections.namedtuple('CertificateKeyPair', 'key crt')


@pytest.fixture(scope="function")
def crt_dir(tmp_path):
    return tmp_path


@pytest.fixture(scope="function")
def local_server(tmp_path, crt_dir):
    # return local server instance
    yield local.LocalServer(crt_name='autossl.example.com', path=crt_dir, acme_dir=tmp_path)


@pytest.fixture(scope="module")
def ca_keypair_path():
    key, crt = tests_util.create_ca_certificate(ca_name='Autossl')
    ca_temp_dir = util.Path(tempfile.mkdtemp())
    ca_crt_path = ca_temp_dir / 'local_ca.crt'
    ca_key_path = ca_temp_dir / 'local_ca.key'

    ca_crt_path.write_bytes(crt)
    ca_key_path.write_bytes(key)

    yield CertificateKeyPair(ca_key_path, ca_crt_path)

    # cleanup temp folders
    shutil.rmtree(str(ca_temp_dir), ignore_errors=True)


@pytest.fixture(scope="function")
def keypair(tmp_path, ca_keypair_path):
    common_name = 'tst.autossl.example.com'
    crt_name = tests_util.get_random_ascii_string()
    key_path = tmp_path.joinpath(crt_name + '.key')
    key_content, csr_path = ssl.generate_csr(name=crt_name, common_name=common_name, output_path=tmp_path)
    crt_path = tmp_path.joinpath(crt_name + '.crt')
    crt_content = tests_util.create_signed_certificate(
        csr_path=csr_path,
        ca_crt_path=ca_keypair_path.crt,
        ca_key_path=ca_keypair_path.key,
        certificate_validity_days=10,
    )

    crt_path.write_bytes(crt_content)
    key_path.write_bytes(key_content)

    yield CertificateKeyPair(key_path, crt_path)


def test_get_description(local_server):
    assert local_server.get_description() == '[LocalServer - {}:{}]'.format(socket.gethostname(), local_server.path)


def test_deploy_cert(local_server, keypair):
    # deploy key + cert + ca cert
    local_server.deploy_cert(key=keypair.key, cert=keypair.crt)

    # ensure files have been created on local server and with proper content
    for source_path in [keypair.key, keypair.crt]:
        server_path = local_server.path.joinpath(local_server.crt_name + source_path.suffix)
        assert server_path.exists()
        assert source_path.read_bytes() == server_path.read_bytes()


@pytest.mark.parametrize('crt_dir', ['/etc/autossl/dummydir12345678'])
def test_deploy_cert_error(local_server, keypair):
    with pytest.raises(exception.DeployCertificateError) as ex_info:
        local_server.deploy_cert(key=keypair.key, cert=keypair.crt)
    assert 'No such file or directory' in str(ex_info.value)


def test_get_certificate_information(local_server, keypair):
    with pytest.raises(exception.CertificateNotFound):
        local_server.get_certificate_information()

    local_server.deploy_cert(key=keypair.key, cert=keypair.crt)

    assert local_server.get_certificate_information() == ssl.SslCertificate().init_from_x509(x509_path=keypair.crt)


def test_create_acme_challenge(local_server):
    # prepare data
    token = tests_util.get_random_ascii_string()
    key_authorization = tests_util.get_random_ascii_string()
    wellknown_path = local_server.acme_dir / token

    # check challenge does not exist yet
    assert not wellknown_path.exists()

    # deploy challenge
    local_server.create_acme_challenge(token=token, key_authorization=key_authorization)

    # ensure challenge exist and with proper value
    assert wellknown_path.exists()
    assert wellknown_path.read_text() == key_authorization


def test_delete_acme_challenge(local_server):
    # prepare data
    token = tests_util.get_random_ascii_string()
    key_authorization = tests_util.get_random_ascii_string()
    wellknown_path = local_server.acme_dir / token

    # deploy challenge
    local_server.create_acme_challenge(token=token, key_authorization=key_authorization)

    # check challenge exists
    assert wellknown_path.exists()

    # delete challenge
    local_server.delete_acme_challenge(token=token)

    # ensure challenge has been deleted
    assert not wellknown_path.exists()
