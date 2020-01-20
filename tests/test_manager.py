# standard packages
import os
import shutil
import tempfile

# external packages
import pytest

# autossl imports
from autossl import exception, manager, ssl, ca_manager, util
from autossl.ca_manager import acme_v2_http01

from tests import util as tests_util


@pytest.fixture(scope='function')
def blueprint_name():
    return 'local.example.com.yaml'


@pytest.fixture(scope='function')
def ssl_manager(blueprint_name):
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
        blueprint_path=tests_util.DATA_PATH / blueprint_name,
        credentials=None,
        staging=True
    )

    # cleanup generated artifacts
    shutil.rmtree(temp_crt_dir, ignore_errors=True)
    shutil.rmtree(temp_crt_dir_2, ignore_errors=True)
    shutil.rmtree(temp_storage_dir, ignore_errors=True)
    shutil.rmtree(temp_tracking_dir, ignore_errors=True)


@pytest.mark.parametrize('blueprint_name, api_class, renewal_supported', [
    ('local.example.com.yaml', ca_manager.base.CaManager, False),
    ('acme.example.com.yaml', acme_v2_http01.AcmeHttp01, True),
])
def test_get_ca_manager_api(ssl_manager, api_class, renewal_supported):
    api = ssl_manager.get_ca_manager_api()
    assert type(api) is api_class
    assert api.is_automated_renewal_supported is renewal_supported


def test_get_api_errors():
    ssl_manager = manager.SslManager()
    with pytest.raises(RuntimeError):
        ssl_manager.get_tracking_api()
    with pytest.raises(RuntimeError):
        ssl_manager.get_storage_api()
    with pytest.raises(RuntimeError):
        ssl_manager.get_ca_storage_api()
    with pytest.raises(RuntimeError):
        ssl_manager.get_server_api(server_parameters=None)


@pytest.mark.parametrize('blueprint_name, is_default_storage', [
    ('local.example.com.yaml', True),
    ('acme.example.com.yaml', False),
])
def test_get_ca_storage_api(ssl_manager, is_default_storage):
    # check where CA storage API is same as default storage or dedicated storage instance
    assert (ssl_manager.get_ca_storage_api() is ssl_manager.get_storage_api()) is is_default_storage


def test_get_renewal_status(ssl_manager):
    to_be_renewed, servers_to_update = ssl_manager.get_renewal_status()
    assert to_be_renewed is True
    assert len(servers_to_update) == 2


def test_request_renewal(ssl_manager):
    # make sure folder is empty at beginning
    assert len(os.listdir(os.environ['AUTOSSL_STORAGE_PATH'])) == 0

    # requesting renewal should save files specified in blueprint in storage: csr, private key, ...
    ssl_manager.request_renewal(
        force=True,  # disable interactive user input
    )

    # check files are saved in storage (the one specified in blueprint)
    assert len(os.listdir(os.environ['AUTOSSL_STORAGE_PATH'])) == 2
    # both key and csr should be saved
    for filename in os.listdir(os.environ['AUTOSSL_STORAGE_PATH']):
        assert filename.rsplit('.', 1)[-1] in ['key', 'csr']


def test_renew_certificate(ssl_manager):
    # should do nothing as automated renewal not supported
    ssl_manager.renew_certificate()


@pytest.mark.parametrize('artifacts_from', ['storage', 'input'])
def test_get_and_check_artifacts_ok(tmp_path, ssl_manager, artifacts_from):
    key_path, crt_path = tests_util.create_autossl_signed_cert(
        ssl_blueprint=ssl_manager.ssl_blueprint,
        output_folder=os.environ['AUTOSSL_STORAGE_PATH'],
    )

    parameters = {
        'folder': str(tmp_path)
    }
    if artifacts_from == 'input':
        parameters.update({
            'certificate_path': crt_path,
            'private_key_path': key_path,
        })

    certificate_path, private_key_path = ssl_manager.get_and_check_artifacts(**parameters)
    assert key_path.read_bytes() == private_key_path.read_bytes()
    assert crt_path.read_bytes() == certificate_path.read_bytes()


def test_get_and_check_artifacts_error(ssl_manager):
    # generate certificates and keys directly in storage path
    key_path, crt_path = tests_util.create_self_signed_certificate(
        crt_name=ssl_manager.ssl_blueprint.name,
        output_path=os.environ['AUTOSSL_STORAGE_PATH'],
        common_name=ssl_manager.ssl_blueprint.certificate.common_name,
        sans=ssl_manager.ssl_blueprint.certificate.sans,
        certificate_validity_days=0,
    )
    key_path_2, crt_path_2 = tests_util.create_self_signed_certificate(
        crt_name=ssl_manager.ssl_blueprint.name + '_2',
        output_path=os.environ['AUTOSSL_STORAGE_PATH'],
        common_name=ssl_manager.ssl_blueprint.certificate.common_name,
        sans=ssl_manager.ssl_blueprint.certificate.sans,
    )

    # test for incompatibility between private key and cert
    with pytest.raises(exception.KeyMismatch) as ex_info:
        ssl_manager.get_and_check_artifacts(
            certificate_path=crt_path,
            private_key_path=key_path_2,
        )
    assert 'Certificate specified does not match private key' in str(ex_info.value)

    # test for expiration of cert
    with pytest.raises(exception.ExpiredCertificate) as ex_info:
        ssl_manager.get_and_check_artifacts(
            certificate_path=crt_path,
            private_key_path=key_path,
        )
    assert 'already expired or expiring soon, renewal needed' in str(ex_info.value)

    with pytest.raises(exception.InvalidTrustChain) as ex_info:
        ssl_manager.get_and_check_artifacts(
            certificate_path=crt_path_2,
            private_key_path=key_path_2,
        )
    assert 'does not match CA certificate specified' in str(ex_info.value)


@pytest.mark.parametrize('blueprint_name', ['local_no_chain_of_trust.example.com.yaml'])
def test_get_and_check_artifacts_error_missing_chain_of_trust(ssl_manager):
    # check missing chain of trust in blueprint when full_chain_deploy explicitly requested for a server
    key_path, crt_path = tests_util.create_self_signed_certificate(
        crt_name=ssl_manager.ssl_blueprint.name,
        output_path=os.environ['AUTOSSL_STORAGE_PATH'],
        common_name=ssl_manager.ssl_blueprint.certificate.common_name,
        sans=ssl_manager.ssl_blueprint.certificate.sans,
    )
    with pytest.raises(exception.SslBlueprintInconsistency) as ex_info:
        ssl_manager.get_and_check_artifacts(
            certificate_path=crt_path,
            private_key_path=key_path,
        )
    assert 'missing chain of trust' in str(ex_info.value)


def test_deploy(ssl_manager):
    key_path, crt_path = tests_util.create_autossl_signed_cert(
        ssl_blueprint=ssl_manager.ssl_blueprint,
        output_folder=os.environ['AUTOSSL_STORAGE_PATH'],
    )

    # deploy them on server
    ssl_manager.deploy(
        certificate_path=crt_path,
        private_key_path=key_path
    )

    to_be_renewed, servers_to_update = ssl_manager.get_renewal_status()
    assert to_be_renewed is False
    assert len(servers_to_update) == 0

    # ensure first server contain only server certificate
    crt_path_server_1 = util.Path(os.environ['AUTOSSL_CRT_PATH']).joinpath(ssl_manager.ssl_blueprint.name + '.crt')
    assert crt_path_server_1.read_text().count('-----BEGIN CERTIFICATE-----') == 1
    assert crt_path_server_1.read_bytes() == crt_path.read_bytes()

    # and 2nd server contains certificate with full chain of trust (2 certificates)
    crt_path_server_2 = util.Path(os.environ['AUTOSSL_CRT_PATH_2']).joinpath(ssl_manager.ssl_blueprint.name + '.crt')
    crt_server_2_content = crt_path_server_2.read_text()
    # we should have 2 certificates: server + CA certificates
    assert crt_server_2_content.count('-----BEGIN CERTIFICATE-----') == 2
    # retrieve server certificate (= the first one) and verify it
    first_certificate = '-----BEGIN CERTIFICATE-----' + crt_server_2_content.split('-----BEGIN CERTIFICATE-----')[1]
    assert first_certificate.strip() == crt_path.read_text().strip()


@pytest.mark.parametrize('api_names', [
    None,  # all default apis
    ['tracking'],
    ['storage'],
    ['tracking', 'storage'],
])
def test_save_and_get_file(tmp_path, ssl_manager, api_names):
    with pytest.raises(exception.NotFound):
        ssl_manager.get_file(
            file_type=ssl.DataType.Certificate,
            file_identifier='dummy',
            output_folder=tmp_path,
        )

    file_content = b'some content'
    ssl_manager.save_file(
        file_type=ssl.DataType.Certificate,
        file_content=file_content,
        api_names=api_names,
    )

    file_identifier = '{}.{}'.format(ssl_manager.ssl_blueprint.name, ssl.DataType.Certificate.value)

    # if specific api specified, ensure file is not present in others
    if api_names:
        # remove input apis from default list
        other_apis = list(set(manager.DEFAULT_APIS) - set(api_names))

        # targeting api where file is not saved raise NotFound exception
        with pytest.raises(exception.NotFound):
            ssl_manager.get_file(
                file_type=ssl.DataType.Certificate,
                file_identifier=file_identifier,
                output_folder=tmp_path,
                api_names=other_apis,
            )

    # here we should find file as same apis than for 'save_file' are used
    file_path_result = ssl_manager.get_file(
        file_type=ssl.DataType.Certificate,
        file_identifier=file_identifier,
        output_folder=tmp_path,
        api_names=api_names,
    )
    assert file_path_result.read_bytes() == file_content


@pytest.mark.parametrize('blueprint_name', ['localca.example.com.yaml'])
def test_automatic_renewal(ssl_manager):
    shutil.copy(str(tests_util.DATA_PATH / 'ca' / 'autossl_ca.key'), os.environ['AUTOSSL_STORAGE_PATH'])
    shutil.copy(str(tests_util.DATA_PATH / 'ca' / 'autossl_ca.crt'), os.environ['AUTOSSL_STORAGE_PATH'])

    # create csr/private key
    ssl_manager.request_renewal(
        force=True,  # disable interactive user input
    )

    # sign certificate with local CA
    ssl_manager.renew_certificate()

    # verify certificate validity
    assert os.system('openssl verify -CAfile %s %s' % (
        tests_util.DATA_PATH / 'ca' / 'autossl_ca.crt',
        os.path.join(os.environ['AUTOSSL_STORAGE_PATH'], 'localca.example.com.crt')
    )) == 0
