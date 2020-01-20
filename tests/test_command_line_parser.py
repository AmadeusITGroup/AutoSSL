import logging

import pytest

import autossl
from autossl import util, __main__

from tests import util as tests_util


def test_display_version():
    assert __main__.display_version() == "Autossl version {version}".format(version=autossl.__version__)


@pytest.mark.parametrize('cli_credentials, credentials_file, result', [
    # full user_password credentials from cli, no credential file
    (['credential_1:my_username:my_pa*ss:wor$d'], None,
     {'credential_1': {'raw_content': 'my_username:my_pa*ss:wor$d'}}),
    # no password from cli, no credential file
    (['credential_1:my_username'], None,
     {'credential_1': {'raw_content': 'my_username'}}),
    # just credential name from cli, no credential file
    (['credential_1'], None,
     {'credential_1': {'raw_content': None}}),
    # full user_password credentials from cli, credential file with cli overriding file for credential_1
    (['credential_1:my_username:my_pa*ss:wor$d'], tests_util.DATA_PATH / 'credentials_file',
     {'credential_1': {'raw_content': 'my_username:my_pa*ss:wor$d'},
      'credential_4_from_file': {'username': 'username_4', 'password': 'password_4', 'extra_parameter': 'extra_param'},
      'credential_5_from_file': {'api_key': '499ebd66-29d6-4992-9ec4-5511a92d248e', 'api_id': '12345'}}),
])
def test_parse_credentials(cli_credentials, credentials_file, result):
    assert __main__.parse_credentials(cli_credentials=cli_credentials, credentials_file=credentials_file) == result


def test_main_parser(capsys):
    # check action is mandatory
    with pytest.raises(SystemExit):
        __main__.parse_arguments([])
    if util.PY2:
        assert 'error: too few arguments' in capsys.readouterr().err
    else:
        assert 'error: the following arguments are required: action' in capsys.readouterr().err

    # default values (as action is mandatory, use 'version' that requires no additional parameter)
    parser = __main__.parse_arguments(['version'])
    assert parser.credentials == []
    assert parser.debug is logging.INFO
    assert parser.staging is False
    assert parser.config is None
    assert parser.blueprint is None

    # parser = __main__.parse_arguments(['-u', r'domain\user:password', '--debug', 'version'])
    # assert parser.credentials == r'domain\user:password'
    # assert parser.debug is True

# TODO
