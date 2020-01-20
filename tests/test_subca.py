# standard packages
import os
import shutil
import tempfile
import collections

# external packages
import pytest

# autossl imports
from autossl import manager, ssl, util

from tests import util as tests_util

CertificateKeyPair = collections.namedtuple('CertificateKeyPair', 'key crt')


@pytest.fixture(scope='module')
def subca_manager():
    # create temporary directories use by blueprint
    temp_crt_dir = tempfile.mkdtemp()
    os.environ['AUTOSSL_CRT_PATH'] = temp_crt_dir
    temp_crt_dir_2 = tempfile.mkdtemp()
    os.environ['AUTOSSL_CRT_PATH_2'] = temp_crt_dir_2

    temp_storage_dir = tempfile.mkdtemp()
    os.environ['AUTOSSL_STORAGE_PATH'] = temp_storage_dir
    temp_tracking_dir = tempfile.mkdtemp()
    os.environ['AUTOSSL_TRACKING_PATH'] = temp_tracking_dir

    yield manager.SslManager(
        global_config=None,
        blueprint_path=tests_util.DATA_PATH / 'subca.example.com.yaml',
        credentials=None,
        staging=True
    )

    # cleanup generated artifacts
    shutil.rmtree(temp_crt_dir, ignore_errors=True)
    shutil.rmtree(temp_crt_dir_2, ignore_errors=True)
    shutil.rmtree(temp_storage_dir, ignore_errors=True)
    shutil.rmtree(temp_tracking_dir, ignore_errors=True)


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


@pytest.fixture(scope="module")
def subca_keypair_path(subca_manager, ca_keypair_path):
    storage_path = util.Path(os.environ['AUTOSSL_STORAGE_PATH'])
    key_path = storage_path.joinpath(subca_manager.ssl_blueprint.name + '.key')
    csr_path = storage_path.joinpath(subca_manager.ssl_blueprint.name + '.csr')
    crt_path = storage_path.joinpath(subca_manager.ssl_blueprint.name + '.crt')
    bundle_path = storage_path.joinpath(subca_manager.ssl_blueprint.name + '.bundle')

    # generate sub-CA certificate request and key
    subca_manager.request_renewal(
        force=True,  # disable interactive user input
    )

    # simulate CA signing
    crt_content = tests_util.create_signed_certificate(
        csr_path=csr_path,
        ca_crt_path=ca_keypair_path.crt,
        ca_key_path=ca_keypair_path.key,
        certificate_validity_days=100
    )
    crt_path.write_bytes(crt_content)
    bundle_path.write_bytes(ca_keypair_path.crt.read_bytes() + crt_content)

    yield CertificateKeyPair(key_path, crt_path)


# valid certificate request
def test_subca_ok(tmp_path, subca_manager, subca_keypair_path):
    # check sub-CA certificate
    subca_crt_path, _ = subca_manager.get_and_check_artifacts()
    subca_cert = ssl.SslCertificate().init_from_x509(x509_path=subca_crt_path)
    assert subca_cert.common_name == 'subca.example.com'

    # sign a new certificate with the sub-CA
    _, csr_path = ssl.generate_csr(name='leafcert',
                                   common_name='domain.subca.example.com',
                                   sans=['domain1.subca.example.com', 'domain2.subca.example.com'],
                                   output_path=str(tmp_path))
    crt_content = tests_util.create_signed_certificate(
        csr_path=csr_path,
        ca_crt_path=subca_keypair_path.crt,
        ca_key_path=subca_keypair_path.key
    )
    crt_path = tmp_path / 'leafcert.crt'
    crt_path.write_bytes(crt_content)

    # check trust chain
    bundle_path = os.path.join(os.environ['AUTOSSL_STORAGE_PATH'], subca_manager.ssl_blueprint.name + '.bundle')
    assert os.system('openssl verify -CAfile %s %s' % (bundle_path, crt_path)) == 0


# invalid certificate request, domains are not part of the authorized names
def test_subca_ko(tmp_path, subca_manager, subca_keypair_path):
    # sign a new certificate with the sub-CA
    _, csr_path = ssl.generate_csr(name='invalidcert',
                                   common_name='domain.other.example.com',
                                   sans=['domain.other.example.com'],
                                   output_path=str(tmp_path))
    crt_content = tests_util.create_signed_certificate(
        csr_path=csr_path,
        ca_crt_path=subca_keypair_path.crt,
        ca_key_path=subca_keypair_path.key
    )
    crt_path = tmp_path / 'invalidcert.crt'
    crt_path.write_bytes(crt_content)

    # check trust chain
    bundle_path = os.path.join(os.environ['AUTOSSL_STORAGE_PATH'], subca_manager.ssl_blueprint.name + '.bundle')
    assert os.system('openssl verify -CAfile %s %s' % (bundle_path, crt_path)) != 0
