from datetime import datetime

import pytest

from autossl import ssl, exception

from tests import util as tests_util


@pytest.mark.parametrize('cert1,cert2,is_same', [
    # fully identical
    ({'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     {'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     True),
    # fully identical but different san order
    ({'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     {'common_name': 'name1', 'sans': ['name3', 'name2'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     True),
    # fully common_name
    ({'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     {'common_name': 'name4', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     False),
    # different san
    ({'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     {'common_name': 'name1', 'sans': ['name2', 'name4'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     False),
    # different expiration
    ({'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2020, 2, 3, 14, 38, 21)},
     {'common_name': 'name1', 'sans': ['name2', 'name3'], 'expiration': datetime(2021, 2, 3, 14, 38, 21)},
     False),
])
def test_ssl_blueprint___eq__(cert1, cert2, is_same):
    assert (ssl.SslCertificate(**cert1) == ssl.SslCertificate(**cert2)) is is_same


def test_missing_blueprint():
    with pytest.raises(IOError):
        ssl.SslBlueprint('dummy/path')


def test_ssl_blueprint_no_server():
    ssl_blueprint = ssl.SslBlueprint(tests_util.DATA_PATH / 'tst.ov.example.com_no-server.yaml')
    assert ssl_blueprint.name == 'auto_tst.autossl.example.com'
    assert ssl_blueprint.certificate.certificate_type == 'OV'
    assert ssl_blueprint.certificate.certificate_authority == 'Sectigo'
    assert ssl_blueprint.certificate.common_name == 'tst.autossl.example.com'
    assert len(ssl_blueprint.servers) == 0


def test_ov_ssl_blueprint():
    ssl_blueprint = ssl.SslBlueprint(tests_util.DATA_PATH / 'tst.ov.example.com.yaml')
    assert ssl_blueprint.name == 'auto_tst.autossl.example.com'
    assert ssl_blueprint.certificate.certificate_type == 'OV'
    assert ssl_blueprint.certificate.certificate_authority == 'Sectigo'
    assert ssl_blueprint.certificate.common_name == 'tst.autossl.example.com'
    assert ssl_blueprint.certificate.renewal_delay == 30
    assert len(ssl_blueprint.servers) == 1
    assert len(ssl_blueprint.certificate.sans) == 5
    assert ssl_blueprint.certificate.organization['company_name'] == 'Autossl corporation'
    assert ssl_blueprint.certificate.organization['street_address'] == 'Newbury street'
    assert ssl_blueprint.certificate.organization['city'] == 'Boston'
    assert ssl_blueprint.certificate.organization['state'] == 'Massachusetts'
    assert ssl_blueprint.certificate.organization['postal_code'] == '02115'
    assert ssl_blueprint.certificate.organization['country_code'] == 'US'


def test_dv_ssl_blueprint():
    ssl_blueprint = ssl.SslBlueprint(tests_util.DATA_PATH / 'tst.dv.example.com.yaml')
    assert ssl_blueprint.name == 'auto_tst.autossl.example.com'
    assert ssl_blueprint.certificate.certificate_type == 'DV'
    assert ssl_blueprint.certificate.certificate_authority == 'LetsEncrypt'
    assert ssl_blueprint.certificate.common_name == 'tst.autossl.example.com'
    assert ssl_blueprint.certificate.renewal_delay == 30
    assert len(ssl_blueprint.servers) == 2
    assert len(ssl_blueprint.certificate.sans) == 5
    assert ssl_blueprint.certificate.organization is None


def test_ssl_blueprint_with_global_config():
    ssl_blueprint = ssl.SslBlueprint(
        yaml_path=tests_util.DATA_PATH / 'tst.ov.example.com_minimal.yaml',
        global_config_path=tests_util.DATA_PATH / 'global_config.yaml',
    )
    assert ssl_blueprint.name == 'auto_tst.autossl.example.com'
    assert ssl_blueprint.certificate.certificate_type == 'DV'
    assert ssl_blueprint.certificate.certificate_authority == 'LetsEncrypt'
    assert ssl_blueprint.certificate.common_name == 'tst.autossl.example.com'
    assert ssl_blueprint.certificate.renewal_delay == 30
    assert len(ssl_blueprint.servers) == 1
    assert len(ssl_blueprint.certificate.sans) == 5
    assert ssl_blueprint.certificate.organization['company_name'] == 'Autossl corporation'
    assert ssl_blueprint.certificate.organization['street_address'] == 'Newbury street'
    assert ssl_blueprint.certificate.organization['city'] == 'Boston'
    assert ssl_blueprint.certificate.organization['state'] == 'Massachusetts'
    assert ssl_blueprint.certificate.organization['postal_code'] == '02115'
    assert ssl_blueprint.certificate.organization['country_code'] == 'US'


def test_ssl_blueprint_no_common_name(tmp_path):
    blueprint_content = u"""
---
name: auto_tst.autossl.example.com

servers:
  - type: autossl.server.local.LocalServer
    parameters:
        path: /etc/ssl/my_certificates

certificate:
  type: DV
  certificate_authority: LetsEncrypt
  san:
    - tst.autossl.example.com
    - uat.tst.autossl.example.com
    - pit.tst.autossl.example.com
...
    """
    blueprint_path = tmp_path / 'blueprint.yaml'
    blueprint_path.write_text(blueprint_content, encoding='utf-8')

    ssl_blueprint = ssl.SslBlueprint(str(blueprint_path))
    assert ssl_blueprint.certificate.common_name is None
    assert len(ssl_blueprint.certificate.sans) == 3


def test_ssl_blueprint_no_san(tmp_path):
    blueprint_content = u"""
---
name: auto_tst.autossl.example.com

servers:
  - type: autossl.server.local.LocalServer
    parameters:
        path: /etc/ssl/my_certificates

certificate:
  type: DV
  certificate_authority: LetsEncrypt
  common_name: tst.autossl.example.com
...
        """
    blueprint_path = tmp_path / 'blueprint.yaml'
    blueprint_path.write_text(blueprint_content, encoding='utf-8')

    ssl_blueprint = ssl.SslBlueprint(str(blueprint_path))
    assert ssl_blueprint.certificate.common_name == 'tst.autossl.example.com'
    assert len(ssl_blueprint.certificate.sans) == 0


def test_ssl_blueprint_no_commmon_name_no_san(tmp_path):
    blueprint_content = u"""
---
name: auto_tst.autossl.example.com

servers:
  - type: autossl.server.local.LocalServer
    parameters:
        path: /etc/ssl/my_certificates

certificate:
  type: DV
  certificate_authority: LetsEncrypt
...
        """
    blueprint_path = tmp_path / 'blueprint.yaml'
    blueprint_path.write_text(blueprint_content, encoding='utf-8')

    with pytest.raises(ValueError):
        ssl.SslBlueprint(str(blueprint_path))


@pytest.mark.parametrize('common_name,is_valid', [
    ('test2_valid-test.example.com', True),
    ('*.example.com', True),
    (' test.example.com', False),
    ('test.example.com ', False),
    ('test.*.com', False),
    ('%1.example.com', False),
])
def test_ssl_blueprint_validate_common_name(tmp_path, common_name, is_valid):
    blueprint_content = u"""
---
name: auto_tst.autossl.example.com

servers:
  - type: autossl.server.local.LocalServer
    parameters:
        path: /etc/ssl/my_certificates

certificate:
  type: DV
  certificate_authority: LetsEncrypt
  common_name: '{}'
...
        """.format(common_name)
    blueprint_path = tmp_path / 'blueprint.yaml'
    blueprint_path.write_text(blueprint_content, encoding='utf-8')

    if is_valid:
        ssl.SslBlueprint(str(blueprint_path))
    else:
        with pytest.raises(ValueError):
            ssl.SslBlueprint(str(blueprint_path))


def test_get_domains():
    ssl_blueprint = ssl.SslBlueprint(tests_util.DATA_PATH / 'tst.dv.example.com.yaml')
    assert ssl_blueprint.domains == {
        'tst.autossl.example.com',
        'uat.tst.autossl.example.com',
        'pit.tst.autossl.example.com',
        'cit.tst.autossl.example.com',
        'mgt.tst.autossl.example.com'
    }


def test_is_domain_matching():
    assert ssl.is_domain_matching('test.example.com', 'test.example.com')
    assert ssl.is_domain_matching('test.example.com', 'test.example.com', True)
    assert ssl.is_domain_matching('test.example.com', 'test.example.com', False)

    assert ssl.is_domain_matching('test.example.com', 'test2.example.com') is False
    assert ssl.is_domain_matching('test.example.com', 'test2.example.com', True) is False
    assert ssl.is_domain_matching('test.example.com', 'test2.example.com', False) is False

    assert ssl.is_domain_matching('test.example.com', '*.example.com') is True
    assert ssl.is_domain_matching('test.example.com', '*.example.com', True) is False
    assert ssl.is_domain_matching('test.example.com', '*.example.com', False) is True


def test_is_domain_list_matching():
    assert ssl.is_domain_list_matching(['test.example.com'], ['test.example.com'])
    assert ssl.is_domain_list_matching(['test.example.com'], ['test.example.com', 'test2.example.com'])
    assert ssl.is_domain_list_matching(['test.example.com', 'test2.example.com'], ['test.example.com']) is False
    assert ssl.is_domain_list_matching(['test.example.com', 'test2.example.com'], ['*.example.com'])
    assert ssl.is_domain_list_matching(
        ['test.example.com', 'test2.example.com'], ['*.example.com'], exact_match=True) is False


def test_get_config():
    ssl_blueprint = ssl.SslBlueprint(tests_util.DATA_PATH / 'tst.dv.example.com.yaml')

    assert ssl_blueprint.get_config(name='tracking', path=['dummy_path'], default=[]) == []
    assert ssl_blueprint.get_config(name='tracking', path=None, default=None) is None
    assert ssl_blueprint.get_config(name='storage', path=None, default=None) == {
        'credentials': 'credential_1',
        'data': [{'type': 'key'}, {'type': 'csr'}, {'type': 'crt'}],
        'parameters': {
            'git_url': 'https://git.autossl.com/git/scm/ssl/certificates.git',
            'config_user_name': 'Test User',
            'config_user_email': 'test.user@autossl.com',
        },
        'type': 'autossl.storage.gitscm.GitStorage'}


def test_check_chain_of_trust(tmp_path):
    crt_path = tmp_path / 'local.crt'
    ca_crt_path = tmp_path / 'local_ca.crt'
    ca_key_path = tmp_path / 'local_ca.key'
    # generate CA certificate
    key, crt = tests_util.create_ca_certificate(ca_name='Autossl')
    ca_crt_path.write_bytes(crt)
    ca_key_path.write_bytes(key)

    # sign a new certificate with the CA
    _, csr_path = ssl.generate_csr(name='autossl_cert', common_name='test.autossl.com', output_path=str(tmp_path))
    crt_content = tests_util.create_signed_certificate(
        csr_path=csr_path,
        ca_crt_path=ca_crt_path,
        ca_key_path=ca_key_path,
    )
    crt_path.write_bytes(crt_content)

    # valid trust chain should no raise any error
    ssl.check_chain_of_trust(
        chain_of_trust=[crt.decode('utf-8')],  # Chain of trust comes normally from SSL blueprint so it not in bytes
        crt_path=crt_path,
    )

    # generate self-signed certificate
    self_signed_key_path, self_signed_crt_path = tests_util.create_self_signed_certificate(
        crt_name="self_signed_local.crt",
        output_path=tmp_path,
        common_name='self_signed.test.autossl.com',
    )

    # self signed certificate should not be validated by this CA
    with pytest.raises(exception.InvalidTrustChain):
        ssl.check_chain_of_trust(
            chain_of_trust=[crt.decode('utf-8')],  # Chain of trust comes normally from SSL blueprint so it not in bytes
            crt_path=self_signed_crt_path,
        )
