import pytest

from autossl.server import base


@pytest.fixture(scope="module")
def base_server():
    # return local server instance
    yield base.Server(crt_name='example.autossl.com')


def test_get_description(base_server):
    with pytest.raises(NotImplementedError):
        base_server.get_description()


def test_deploy_cert(base_server):
    with pytest.raises(NotImplementedError):
        base_server.deploy_cert(key=None, cert=None, chain=None)


def test_create_acme_challenge(base_server):
    with pytest.raises(NotImplementedError):
        base_server.create_acme_challenge(token=None, key_authorization=None)


def test_delete_acme_challenge(base_server):
    with pytest.raises(NotImplementedError):
        base_server.delete_acme_challenge(token=None)


def test_get_certificate_information(base_server):
    with pytest.raises(NotImplementedError):
        base_server.get_certificate_information()


def test_is_same(base_server):
    with pytest.raises(NotImplementedError):
        base_server.is_same(common_name=None, sans=None, exact_match=False)


def test_is_expired(base_server):
    with pytest.raises(NotImplementedError):
        base_server.is_expired()
