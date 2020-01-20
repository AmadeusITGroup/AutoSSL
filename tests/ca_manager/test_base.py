import pytest

from autossl.ca_manager import base


@pytest.fixture(scope="module")
def ca_manager():
    yield base.CaManager(ca_config=None, staging=True, storage_api=None)


def test_automated_renewal_supported(ca_manager):
    assert ca_manager.is_automated_renewal_supported is False


def test_get_signed_certificate(ca_manager):
    with pytest.raises(NotImplementedError):
        ca_manager.get_signed_certificate(ssl_blueprint=None, csr_path=None, servers_api=None)
