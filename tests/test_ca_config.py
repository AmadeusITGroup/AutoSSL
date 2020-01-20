import pytest

from autossl import ssl

from tests import util as tests_util


@pytest.fixture(scope='function')
def ssl_blueprint():
    yield ssl.SslBlueprint(
        yaml_path=tests_util.DATA_PATH / 'tst.ov.example.com_minimal.yaml',
        global_config_path=tests_util.DATA_PATH / 'global_config.yaml',
    )


def test_ca_config(ssl_blueprint):
    assert ssl_blueprint.ca_config.is_acme_supported()
    assert ssl_blueprint.ca_config.get_supported_certificate_types() == ['DV']
    assert ssl_blueprint.ca_config.get_acme_api(staging=True) == 'https://acme-staging-v02.api.letsencrypt.org'
    assert ssl_blueprint.ca_config.get_acme_api(staging=False) == 'https://acme-v02.api.letsencrypt.org'
    assert ssl_blueprint.ca_config.get_storage_config() == {
        'type': 'autossl.storage.local.LocalFileStorage',
        'name': 'lets_encrypt_account_key',
        'parameters': {
            'path': '/etc/keys'
        },
    }
    assert len(ssl_blueprint.ca_config.get_chain_of_trust()) == 2
