try:
    import unittest.mock as mock
except ImportError:
    import mock

import pytest

from autossl import credential, util

from tests import util as tests_util


def test_get_credentials_already_retrieved_once():
    username = tests_util.get_random_ascii_string(10)
    password = tests_util.get_random_ascii_string(10)
    user_password_credential = credential.get_credentials(
        name='credential_1',
        global_config=None,
        credentials={'credential_1': {
            'type': credential.CredentialType.UserPassword,
            'username': username,
            'password': password,
        }},
        extra_parameters=None,
    )
    assert user_password_credential == {
        'type': credential.CredentialType.UserPassword,
        'username': username,
        'password': password,
    }


def test_get_credentials_unsupported_credential_type():
    with pytest.raises(KeyError):
        credential.get_credentials(
            name='credential_1',
            global_config={'credential_1': {'type': 'not_supported_type'}},
            credentials={},
            extra_parameters=None,
        )


def test_get_credentials_with_extra_parameters():
    # username/password
    assert credential.get_credentials(
        name='credential_1',
        global_config={'credential_1': {'type': credential.CredentialType.UserPassword.name}},
        credentials={'credential_1': {'raw_content': 'my_username:my_pa*ss:wor$d'}},
        extra_parameters={'domain': 'corp'},
    ) == {
        'type': credential.CredentialType.UserPassword,
        'username': 'my_username',
        'password': 'my_pa*ss:wor$d',
        'domain': 'corp',
    }

    # check apiKey credential type with custom separator
    assert credential.get_credentials(
        name='api_credential',
        global_config={'api_credential': {'type': credential.CredentialType.ApiKeyAndId.name, 'separator': '/'}},
        credentials={'api_credential': {'raw_content': '499ebd66-29d6-4992-9ec4-5511a92d248e/12345'}},
        extra_parameters={'additional_identifier': 'corp_789'},
    ) == {
        'type': credential.CredentialType.ApiKeyAndId,
        'api_key': '499ebd66-29d6-4992-9ec4-5511a92d248e',
        'api_id': '12345',
        'additional_identifier': 'corp_789',
    }


def test_get_user_password_from_user_input():
    username = tests_util.get_random_ascii_string(10)
    password = tests_util.get_random_ascii_string(10)

    mock_input = '__builtin__.raw_input' if util.PY2 else 'builtins.input'
    with mock.patch(mock_input, return_value=username), mock.patch('getpass.getpass', return_value=password):
        user_password_credential = credential.get_user_password(name='credential_1')
    assert user_password_credential == {
        'type': credential.CredentialType.UserPassword,
        'username': username,
        'password': password,
    }


@pytest.mark.parametrize('credentials_dict, username, password', [
    ({'credential_1': {'username': 'my_username', 'password': 'my_password'}}, 'my_username', 'my_password'),
    ({'credential_1': {'raw_content': 'my_username:my_pa*ss:wor$d'}}, 'my_username', 'my_pa*ss:wor$d'),
])
def test_get_user_password_from_credentials_list(credentials_dict, username, password):
    user_password_credential = credential.get_user_password(name='credential_1', credentials=credentials_dict)
    assert user_password_credential == {
        'type': credential.CredentialType.UserPassword,
        'username': username,
        'password': password,
    }


def test_get_credentials_from_env_variables(monkeypatch):
    # expected credentials
    username = 'my_username_1'
    password = 'my_pa*ss:wor$d_+'

    # temporarily set env variable with credentials
    monkeypatch.setenv('CREDENTIAL_1_USERNAME', username)
    monkeypatch.setenv('CREDENTIAL_1_PASSWORD', password)

    assert credential.get_credentials(
        name='credential_1',
        global_config={'credential_1': {'type': credential.CredentialType.UserPassword.name}},
        credentials={},
    ) == {
        'type': credential.CredentialType.UserPassword,
        'username': username,
        'password': password,
    }
