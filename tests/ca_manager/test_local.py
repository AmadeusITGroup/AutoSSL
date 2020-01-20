import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509

from autossl.ca_manager import local as local_ca
from autossl.storage import local as local_storage
from autossl import ssl
from tests import util as tests_util


@pytest.fixture(scope="function")
def storage(tmp_path):
    yield local_storage.LocalFileStorage(path=str(tmp_path))


@pytest.fixture(scope="function")
def ca_manager(storage):
    ca_key, ca_crt = tests_util.create_ca_certificate(ca_name='Autossl')
    storage.save_data(name='ca_key', data_type=ssl.DataType.PrivateKey, content=ca_key)
    storage.save_data(name='ca_crt', data_type=ssl.DataType.Certificate, content=ca_crt)
    yield local_ca.LocalCa(ca_config=None,
                           staging=True,
                           storage_api=storage,
                           ca_private_key='ca_key',
                           ca_certificate='ca_crt')


def test_automated_renewal_supported(ca_manager):
    assert ca_manager.is_automated_renewal_supported is True


@pytest.mark.parametrize('common_name', ['test.autossl.com'])
def test_get_signed_certificate(ca_manager, common_name, tmp_path):
    _, csr_path = ssl.generate_csr(name='autossl_cert',
                                   common_name=common_name,
                                   output_path=tmp_path)
    crt = ca_manager.get_signed_certificate(ssl_blueprint=None, csr_path=csr_path, servers_api=None)

    # check CRT
    x509_object = x509.load_pem_x509_certificate(data=crt, backend=default_backend())
    assert len(x509_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1
    assert x509_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name
