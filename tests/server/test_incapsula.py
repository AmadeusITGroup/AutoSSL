"""
Tests for Incapsula server implementation
"""
import base64
import collections
import datetime
import json
try:
    from unittest import mock  # py3
except ImportError:
    import mock  # py2
import pytest

from autossl import exception, ssl, util
from autossl.server import incapsula

from tests import util as tests_util

DATA_PATH = util.Path(__file__).parent / 'data'


CertificateKeyPair = collections.namedtuple('CertificateKeyPair', 'key crt')
SITE_ID = '12345678'
API_KEY = '6f4d1878-f2c6-446b-8932-636b8f1705a7'
API_ID = '12345'
CHAIN_OF_TRUST = [
    """"-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/MSQwIgYDVQQK
ExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4X
DTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0NlowSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxl
dCdzIEVuY3J5cHQxIzAhBgNVBAMTGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4
S0EFq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8SMx+yk13
EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0Z8h/pZq4UmEUEz9l6YKH
y9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWAa6xK8xuQSXgvopZPKiAlKQTGdMDQMc2P
MTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQAB
o4IBfTCCAXkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEE
czBxMDIGCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNvbTA7
BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9kc3Ryb290Y2F4My5w
N2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAwVAYDVR0gBE0wSzAIBgZngQwBAgEw
PwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcCARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNy
eXB0Lm9yZzA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9P
VENBWDNDUkwuY3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJouM2VcGfl96S8
TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/wApIvJSwtmVi4MFU5aMqrSDE
6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwuX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPM
TZ+sOPAveyxindmjkW8lGy+QsRlGPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M
+X+Q7UNKEkROb3N6KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
""",
    """"-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/MSQwIgYDVQQK
ExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4X
DTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVowPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1
cmUgVHJ1c3QgQ28uMRcwFQYDVQQDEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmT
rE4Orz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEqOLl5CjH9
UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9bxiqKqy69cK3FCxolkHRy
xXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40d
utolucbY38EVAjqr2m7xPi71XAicPNaDaeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQ
MA0GCSqGSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69ikug
dB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXrAvHRAosZy5Q6XkjE
GB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZzR8srzJmwN0jP41ZL9c8PDHIyh8bw
RLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubS
fZGL+T0yjWW06XyxV3bqxbYoOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
"""
]


class MockResponse:
    """"Mock requests.Session response object"""

    def __init__(self, content_path):
        self.status_code = 200
        self.content = content_path.read_text()

    def json(self):
        return json.loads(self.content)


@pytest.fixture(scope="function")
def incapsula_json_response_first_call():
    return 'incapsula_get_site_ok.json'


@pytest.fixture(scope="function")
def incapsula_json_response_second_call():
    return 'incapsula_get_site_ok.json'


# use function scope to make sure we can check only the mock calls of current scenario
@pytest.fixture(scope="function")
def incapsula_site(incapsula_json_response_first_call, incapsula_json_response_second_call):
    # patched_session will have a list attribute mock_calls that will contain (after __init__) at least the following:
    # mock_calls[0] is Session object creation
    # mock_calls[1] is the call to Session.mount() in order to enable http retries
    # mock_calls[2] is the retrieval of Incapsula site information
    with mock.patch('autossl.server.incapsula.requests.Session') as patched_session:
        # return local server instance
        patched_session.return_value = mock.MagicMock(post=mock.MagicMock(
                side_effect=[
                    # first call to retrieve site config is always ok
                    MockResponse(content_path=DATA_PATH / incapsula_json_response_first_call),
                    # second call can return either ok or an error
                    MockResponse(content_path=DATA_PATH / incapsula_json_response_second_call),
                    # we can have extra calls in case of retries, let's consider retry works
                    MockResponse(content_path=DATA_PATH / 'incapsula_get_site_ok.json'),
                ]
            )
        )
        incapsula_server = incapsula.IncapsulaSite(API_KEY, API_ID, site_id=SITE_ID, crt_name='tst.example.autossl.com')

        yield incapsula_server, patched_session


@pytest.fixture(scope="function")
def keypair(tmp_path):
    """Generate SSL keypair: private key + certificate"""
    common_name = 'tst.autossl.example.com'
    crt_name = tests_util.get_random_ascii_string()
    key_path = tmp_path / (crt_name + '.key')
    key_content, csr_path = ssl.generate_csr(name=crt_name, common_name=common_name, output_path=tmp_path)
    crt_path = tmp_path / (crt_name + '.crt')
    crt_content = tests_util.create_signed_certificate(
        csr_path=csr_path,
        certificate_validity_days=10,
    )
    crt_path.write_bytes(crt_content)
    key_path.write_bytes(key_content)

    yield CertificateKeyPair(key_path, crt_path)


def test_init(incapsula_site):
    # ensure incapsula_server api is well initialized
    assert incapsula_site[0].api_key == API_KEY
    assert incapsula_site[0].api_id == API_ID
    assert incapsula_site[0].site_id == SITE_ID
    assert incapsula_site[0].headers == {'x-API-Key': API_KEY, 'x-API-Id': API_ID}
    assert incapsula_site[0].basic_params == {'site_id': SITE_ID}
    assert isinstance(incapsula_site[0].site_status, dict)

    # ensure rest query to incapsula is well formed
    # mock_calls[0] is Session object creation
    # mock_calls[1] is the call to Session.mount() in order to enable http retries
    assert incapsula_site[1].mock_calls[2] == mock.call().post(
        headers={'x-API-Key': API_KEY, 'x-API-Id': API_ID},
        data={'site_id': SITE_ID},
        url='https://my.incapsula.com:443/api/prov/v1/sites/status'
    )


def test_get_description(incapsula_site):
    assert incapsula_site[0].get_description() == '[IncapsulaSite - tst.example.autossl.com (12345678)]'


@pytest.mark.parametrize('incapsula_json_response_second_call', [
    'incapsula_get_site_ok.json',
    'incapsula_get_site_error.json'
])
def test_deploy_cert(incapsula_site, keypair):
    # deploy key + cert
    incapsula_site[0].deploy_cert(key=keypair.key, cert=keypair.crt)

    # ensure rest query to incapsula is well formed
    assert incapsula_site[1].mock_calls[3] == mock.call().post(
        headers={'x-API-Key': API_KEY, 'x-API-Id': API_ID},
        data={
            'site_id': SITE_ID,
            'certificate': base64.b64encode(keypair.crt.read_bytes()),
            'private_key': base64.b64encode(keypair.key.read_bytes()),
        },
        url='https://my.incapsula.com:443/api/prov/v1/sites/customCertificate/upload'
    )


def test_get_certificate_information(incapsula_site):
    certificate_information = incapsula_site[0].get_certificate_information()

    assert certificate_information.common_name == 'tst.example.autossl.com'
    assert certificate_information.sans == []
    assert certificate_information.expiration == datetime.datetime(
        year=2019, month=3, day=17, hour=9, minute=17, second=43)


# customize incaspula deploy to return an error
@pytest.mark.parametrize('incapsula_json_response_first_call', ['incapsula_get_site_no_ssl_certificate.json'])
def test_get_certificate_information_no_custom_ssl_certificate(incapsula_site):
    with pytest.raises(exception.CertificateNotFound):
        incapsula_site[0].get_certificate_information()


def test_is_same(incapsula_site):
    assert incapsula_site[0].is_same(common_name='tst.example.autossl.com', sans=None) is True
    assert incapsula_site[0].is_same(common_name=None, sans=['tst.example.autossl.com']) is True
    assert incapsula_site[0].is_same(common_name=None, sans=['test1.tst.example.autossl.com',
                                                             'test2.tst.example.autossl.com',
                                                             'tst.example.autossl.com']) is True
    assert incapsula_site[0].is_same(common_name='*.example.autossl.com', sans=None) is True
    assert incapsula_site[0].is_same(common_name='test2.tst.example.autossl.com', sans=None) is False
    assert incapsula_site[0].is_same(common_name=None, sans=['test2.tst.example.autossl.com',
                                                             'test-3.tst.example.autossl.com']) is False


def test_create_acme_challenge(incapsula_site):
    # call should do nothing and should not fail
    incapsula_site[0].create_acme_challenge(token=None, key_authorization=None)

    # ensure no external call has been made
    assert len(incapsula_site[1].mock_calls) == 3


def test_delete_acme_challenge(incapsula_site):
    # call should do nothing and should not fail
    incapsula_site[0].delete_acme_challenge(token=None)

    # ensure no external call has been made
    assert len(incapsula_site[1].mock_calls) == 3
