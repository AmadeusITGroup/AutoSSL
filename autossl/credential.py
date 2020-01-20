from enum import Enum
import getpass
import os

from . import util


class CredentialType(Enum):
    """list of credentials types supported"""
    UserPassword = 'user_password'
    ApiKeyAndId = 'api_key_and_api_id'


def get_credentials(name, global_config, credentials, extra_parameters=None):
    """Get structured form of specified credential based on its type and ready to be passed to any api

    :param name: name of the credential
    :type name: str
    :param global_config: credential global configuration
    :type global_config: dict
    :param credentials: structured credentials  dict
    :type credentials: dict
    :param extra_parameters: extra parameters to add to current credential
    :type extra_parameters: dict
    :return: structured credentials
    :rtype: dict
    """
    result = credentials.get(name, {})
    if result.get('type') is None:
        # retrieve credentials global configuration
        credentials_config = global_config[name]

        # retrieve credentials based on credentials type
        # credential type should be valid as already verified as part of ssl blueprint validation
        credential_type = CredentialType[credentials_config['type']]

        # ability to customize fields separator in command line from global credential section, default to ':'
        separator = credentials_config.get('separator')

        # no need for an 'else' as every credential type part of the enum is expected to be implemented here
        if credential_type == CredentialType.UserPassword:
            result = get_user_password(name=name, credentials=credentials, separator=separator)
        elif credential_type == CredentialType.ApiKeyAndId:
            result = get_api_key_and_id(name=name, credentials=credentials, separator=separator)

        # update custom parameters
        if extra_parameters:
            result.update(extra_parameters)

    return result


def _get_credential(name, credentials, credential_type, separator, parameters, sensitive_params=None):
    # initialize result with correct structure this credential type
    result = {
        'type': credential_type,
    }
    for parameter in parameters:
        result[parameter] = None

    # check first if this credential is already in input credentials dict,
    # this can happen in 2 cases:
    # 1. if provided in command line input
    # 2. if it has been already used once
    if credentials and name in credentials:
        result.update(credentials[name])

    # credential is not complete, let try different ways to get missing information
    missing_parameters = [param_name for param_name in result if result[param_name] is None]
    if any(missing_parameters):
        # first, if we have a raw content to parse
        raw_content = result.get('raw_content')
        if raw_content is not None:
            # try to split as much as we expect parameters, using specified separator or ':' by default
            credentials_input = raw_content.split(separator or ':', len(parameters) - 1)
            for index, parameter in enumerate(parameters):
                if len(credentials_input) >= index + 1:
                    result[parameter] = credentials_input[index]
            # only keep formatted data
            del result['raw_content']

        # finally if we still miss some data
        for parameter in parameters:
            if result[parameter] is None:
                # check environment variables first
                # format for env variable name is "CREDENTIAL_NAME + _ + PARAMETER_NAME"
                result[parameter] = os.getenv('{}_{}'.format(name, parameter).upper())

            # and finally, if still missing, ask interactively to the user
            if result[parameter] is None:
                prompt_str = '{} {}:'.format(name.title(), parameter)
                if parameter in sensitive_params or []:
                    result[parameter] = getpass.getpass(prompt_str)
                else:
                    result[parameter] = raw_input(prompt_str) if util.PY2 else input(prompt_str)  # noqa

    return result


def get_user_password(name, credentials=None, separator=None):
    return _get_credential(
        name=name,
        credentials=credentials,
        credential_type=CredentialType.UserPassword,
        separator=separator,
        parameters=['username', 'password'],
        sensitive_params=['password']
    )


def get_api_key_and_id(name, credentials=None, separator=None):
    return _get_credential(
        name=name,
        credentials=credentials,
        separator=separator,
        credential_type=CredentialType.ApiKeyAndId,
        parameters=['api_key', 'api_id'],
        sensitive_params=['api_key', 'api_id']
    )
