import collections
import os
import shutil
import tempfile

import pytest

from autossl import __main__, ssl, util

from tests import util as tests_util

EnvConfig = collections.namedtuple('EnvConfig', 'server_path storage_path tracking_path')


def get_default_options(ssl_blueprint_path=None):
    """Convenient method for testing command line, that provides minimum necessary command line options"""
    return ['--staging', '--blueprint', str(ssl_blueprint_path)]


@pytest.fixture(scope='function')
def ssl_blueprint():
    """Provide bluepring instance using local apis"""
    yield ssl.SslBlueprint(yaml_path=tests_util.DATA_PATH / 'local.example.com.yaml')


@pytest.fixture(scope='function')
def env_config():
    # create temporary directories use by blueprint
    temp_crt_dir = tempfile.mkdtemp()
    os.environ['AUTOSSL_CRT_PATH'] = temp_crt_dir
    temp_storage_dir = tempfile.mkdtemp()
    os.environ['AUTOSSL_STORAGE_PATH'] = temp_storage_dir
    temp_tracking_dir = tempfile.mkdtemp()
    os.environ['AUTOSSL_TRACKING_PATH'] = temp_tracking_dir

    yield EnvConfig(util.Path(temp_crt_dir), util.Path(temp_storage_dir), util.Path(temp_tracking_dir))

    # cleanup generated artifacts
    shutil.rmtree(temp_crt_dir, ignore_errors=True)
    shutil.rmtree(temp_storage_dir, ignore_errors=True)


def test_main_version(capsys):
    __main__.main(['version'])
    assert capsys.readouterr().out.rstrip() == __main__.display_version()


def test_main_check_with_invalid_blueprint_path():
    with pytest.raises(IOError):
        __main__.main(get_default_options(ssl_blueprint_path='/does/not/exist') + ['check'])


def test_main_check_with_blueprint_file(env_config, ssl_blueprint):
    __main__.main(get_default_options(ssl_blueprint.blueprint_path) + ['check'])


def test_main_renew(env_config, ssl_blueprint):
    # ensure nothing generated yet
    assert len(os.listdir(str(env_config.server_path))) == 0
    assert len(os.listdir(str(env_config.server_path))) == 0
    assert len(os.listdir(str(env_config.storage_path))) == 0

    # request renewal
    __main__.main(get_default_options(ssl_blueprint.blueprint_path) + ['renew', '--force'])

    # no crt generated yet
    assert len(os.listdir(str(env_config.server_path))) == 0
    # but we should have stored new private key and csr
    assert len(os.listdir(str(env_config.storage_path))) == 2
    for file_ in env_config.storage_path.iterdir():
        assert file_.suffix in ['.key', '.csr']


def test_main_deploy_all_servers(env_config, ssl_blueprint):
    # generate valid key + associated crt
    tests_util.create_autossl_signed_cert(
        ssl_blueprint=ssl_blueprint,
        output_folder=env_config.storage_path,
    )

    # perform deployment
    __main__.main(get_default_options(ssl_blueprint.blueprint_path) + ['deploy', '--all-servers'])

    # crt and key should be deployed on server
    assert len(os.listdir(str(env_config.server_path))) == 2
    for file_ in os.listdir(str(env_config.server_path)):
        assert file_.split('.')[-1] in ['key', 'crt']

    # and we should have stored private key, csr and crt
    assert len(os.listdir(str(env_config.storage_path))) == 3
    for file_ in os.listdir(str(env_config.storage_path)):
        assert file_.split('.')[-1] in ['key', 'csr', 'crt']

    __main__.main(get_default_options(ssl_blueprint.blueprint_path) + ['check'])


def test_main_deploy_invalid_servers_only(env_config, ssl_blueprint):
    assert len(os.listdir(str(env_config.server_path))) == 0
    # generate valid key + associated crt
    tests_util.create_autossl_signed_cert(
        ssl_blueprint=ssl_blueprint,
        output_folder=env_config.storage_path,
    )

    __main__.main(get_default_options(ssl_blueprint.blueprint_path) + ['deploy'])

    assert len(os.listdir(str(env_config.server_path))) == 2
