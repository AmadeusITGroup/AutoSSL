import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography import x509
import pytest

from autossl import ssl
from tests import util as tests_util


@pytest.mark.parametrize('common_name,sans',
                         [
                             ('example.com', []),
                             ('example.com', ['example.com', 'www.example.com', 'test.example.com']),
                             (None, ['example.com', 'www.example.com', 'test.example.com']),
                         ]
                         )
def test_generate_dv_csr_with_key_creation(tmp_path, common_name, sans):
    name = 'auto_example.com'
    key_content, csr_path = ssl.generate_csr(
        name=name,
        common_name=common_name,
        sans=sans,
        key_content=None,
        output_path=str(tmp_path),
    )

    # check key + csr files have been created
    assert key_content.startswith(b'-----BEGIN RSA PRIVATE KEY-----\n')
    assert csr_path.is_file()

    # check csr file has right name
    assert csr_path.name == '%s.csr' % name

    # load csr first
    csr = x509.load_pem_x509_csr(data=csr_path.read_bytes(), backend=default_backend())

    # check content of CSR
    if common_name is not None:
        assert len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1
        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name
    else:
        # common name is optional
        assert len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 0

    assert sans == [dns_name.value
                    for dns_name in csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value]


@pytest.mark.parametrize('common_name,sans',
                         [
                             ('example.com', []),
                             ('example.com', ['example.com', 'www.example.com', 'test.example.com']),
                             (None, ['example.com', 'www.example.com', 'test.example.com']),
                          ]
                         )
def test_generate_dv_csr_with_existing_key(tmp_path, common_name, sans):
    name = 'auto_example.com'
    existing_key_content = tests_util.DATA_PATH.joinpath('auto_example.com.key').read_bytes()
    key_content, csr_path = ssl.generate_csr(
        name=name,
        common_name=common_name,
        sans=sans,
        key_content=existing_key_content,
        output_path=str(tmp_path),
    )

    # check that returned key content is same than input key content
    assert key_content == existing_key_content

    # check csr files has been created
    assert csr_path.is_file()

    # check csr file has right name
    assert csr_path.name == '%s.csr' % name

    # load csr first
    csr = x509.load_pem_x509_csr(data=csr_path.read_bytes(), backend=default_backend())

    # check content of CSR
    if common_name is not None:
        assert len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1
        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name
    else:
        # common name is optional
        assert len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 0

    assert sans == [dns_name.value
                    for dns_name in csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value]


def test_generate_two_csr_with_same_key(tmp_path):
    name = 'auto_example.com'
    common_name = 'example.com'
    sans = ['example.com', 'www.example.com', 'test.example.com']
    key_content, csr_path = ssl.generate_csr(
        name=name,
        common_name=common_name,
        sans=sans,
        key_content=None,
        output_path=str(tmp_path),
    )
    # generate 2nd csr with same key
    key_content, csr2_path = ssl.generate_csr(
        name='test_' + name,
        common_name=common_name,
        sans=sans,
        key_content=key_content,
        output_path=str(tmp_path),
    )

    # csr should be exactly the same if same key and content are used
    assert csr_path.read_bytes() == csr2_path.read_bytes()


def test_generate_ov_csr(tmp_path):
    name = 'auto_example.com'
    common_name = 'example.com'
    sans = ['example.com', 'www.example.com', 'test.example.com']
    company_name = 'Autossl corporation'
    street_address = 'Newbury street'
    city = 'Boston'
    state = 'Massachusetts'
    postal_code = '02115'
    country_code = 'US'
    email_address = 'test@autossl.com'

    key_content, csr_path = ssl.generate_csr(
        name=name,
        common_name=common_name,
        company_name=company_name,
        street_address=street_address,
        city=city,
        state=state,
        postal_code=postal_code,
        country_code=country_code,
        email_address=email_address,
        sans=sans,
        key_content=None,
        output_path=str(tmp_path),
    )

    # check key + csr files have been created
    assert key_content.startswith(b'-----BEGIN RSA PRIVATE KEY-----\n')
    assert csr_path.is_file()

    # check csr file has right name
    assert csr_path.name == '%s.csr' % name

    # load csr first
    csr = x509.load_pem_x509_csr(data=csr_path.read_bytes(), backend=default_backend())

    # check content of CSR
    # common name
    assert len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name
    # sans
    assert sans == [dns_name.value
                    for dns_name in csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value]
    # organization
    assert csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == company_name
    assert csr.subject.get_attributes_for_oid(NameOID.STREET_ADDRESS)[0].value == street_address
    assert csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == city
    assert csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == state
    assert csr.subject.get_attributes_for_oid(NameOID.POSTAL_CODE)[0].value == postal_code
    assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == country_code
    assert csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value == email_address


@pytest.mark.parametrize('common_name,sans',
                         [
                             ('example.com', []),
                             ('example.com', ['example.com', 'www.example.com', 'test.example.com']),
                             (None, ['example.com', 'www.example.com', 'test.example.com']),
                          ]
                         )
def test_get_domains_from_x509(tmp_path, common_name, sans):
    name = 'auto_example.com'
    key_path, csr_path = ssl.generate_csr(
        name=name,
        common_name=common_name,
        sans=sans,
        key_content=None,
        output_path=str(tmp_path),
    )

    expected_domains = set(sans)
    if common_name is not None:
        expected_domains.add(common_name)

    assert ssl.get_domains_from_x509(csr_path, file_type=ssl.DataType.CertificateSigningRequest) == expected_domains


@pytest.mark.parametrize('common_name, sans, result', [
    ("test.autossl.com", ["san1.autossl.com", "san2.autossl.com"],
        {"test.autossl.com", "san1.autossl.com", "san2.autossl.com"}),
    (None, ["san1.autossl.com", "san2.autossl.com"], {"san1.autossl.com", "san2.autossl.com"}),
    ("test.autossl.com", None, {"test.autossl.com"}),
    ("test.autossl.com", [], {"test.autossl.com"}),
    ("test.autossl.com", ["test.autossl.com", "san1.autossl.com"], {"test.autossl.com", "san1.autossl.com"}),
    (None, ["san1.autossl.com", "san2.autossl.com"], {"san1.autossl.com", "san2.autossl.com"}),
])
def test_get_domains(common_name, sans, result):
    assert ssl.get_domains(common_name=common_name, sans=sans) == result


def test_get_expiration():
    assert ssl.get_expiration(crt_path=tests_util.DATA_PATH / 'test.crt') == datetime.datetime(2018, 2, 5, 20, 5, 22)


def test_check_certificate_with_key():
    # CRT and KEY are matching
    assert ssl.check_certificate_with_key(key_path=tests_util.DATA_PATH / 'test.key',
                                          crt_path=tests_util.DATA_PATH / 'test.crt') is True

    # CRT that does not match KEY
    assert ssl.check_certificate_with_key(key_path=tests_util.DATA_PATH / 'auto_example.com.key',
                                          crt_path=tests_util.DATA_PATH / 'test.crt') is False

    # invalid key path
    with pytest.raises(IOError):
        ssl.check_certificate_with_key(key_path=tests_util.DATA_PATH / 'dummy.key',
                                       crt_path=tests_util.DATA_PATH / 'test.crt')

    # invalid crt path
    with pytest.raises(IOError):
        ssl.check_certificate_with_key(key_path=tests_util.DATA_PATH / 'test.key',
                                       crt_path=tests_util.DATA_PATH / 'dummy.crt')


@pytest.mark.parametrize('common_name,sans,validity_days',
                         [
                            ('test.autossl.com', [], 60),
                            ('test.autossl.com', ['example.com', 'www.example.com', 'test.example.com'], 60),
                            ('example.com', [], 0),
                          ]
                         )
def test_cert_sign(tmp_path, common_name, sans, validity_days):
    ca_key, ca_crt = tests_util.create_ca_certificate(ca_name='Autossl')
    _, csr_path = ssl.generate_csr(
        name='autossl_cert',
        common_name=common_name,
        sans=sans,
        output_path=str(tmp_path),
    )

    signed_crt = ssl.sign(csr=csr_path.read_bytes(), ca_key=ca_key, ca_cert=ca_crt, validity_days=validity_days)

    # load CRT
    x509_object = x509.load_pem_x509_certificate(data=signed_crt, backend=default_backend())

    # check content of CRT
    assert len(x509_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1
    assert x509_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name
    assert sans == [dns_name.value for dns_name in
                    x509_object.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value]
