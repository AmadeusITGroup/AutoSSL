from __future__ import absolute_import, print_function

import argparse
import fnmatch
import logging
import os
from six.moves import configparser
import sys

import autossl
from autossl import manager, util

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger('autossl')


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(description=autossl.__description__)

    parser.add_argument('--credentials', action='append', default=[],
                        help='Generic user/password credentials. Format: name:user:password')

    parser.add_argument('--credentials-file',
                        type=util.Path,
                        default=util.Path('~/.autossl').expanduser(),
                        help='Local file to store credentials.')

    parser.add_argument('--debug', action="store_const", const=logging.DEBUG, default=logging.INFO,
                        help='Use DEBUG log level rather than INFO')

    parser.add_argument("--staging", action='store_true',
                        help="Testing mode (for example, use staging CA servers)")

    parser.add_argument("--config",
                        type=util.Path,
                        help="Path to a file containing common configuration. Same format than SSL blueprint.")

    parser.add_argument("--blueprint",
                        required=False,
                        type=util.Path,
                        help="Path to the definition of certificates. Can be single blueprint or a folder")

    action_subparser = parser.add_subparsers(title="action", dest="action")
    action_subparser.required = True  # needed for python3 compatibility

    ################
    # VERSION
    ################
    action_subparser.add_parser("version", help="Display autossl current version")

    ########################################
    # Parser to check if certificate needs to be renewed
    ########################################
    action_subparser.add_parser("check", help="Check for expired certificate.")

    ########################################
    # Parser to request certificate renewal
    ########################################
    action_parser_renew = action_subparser.add_parser("renew", help="Request certificate renewal")
    action_parser_renew.add_argument("--force",
                                     action='store_true',
                                     help="Renew certificate now (even if current one is still valid)")

    ########################################
    # Parser to deploy certificate on server
    ########################################
    action_parser_deploy = action_subparser.add_parser("deploy", help="Deploy certificate")
    action_parser_deploy.add_argument('-t', '--tracking-record',
                                      help='Tracking record ID for the change, '
                                           'and also potentially containing certificate to deploy.')
    action_parser_deploy.add_argument('-k', '--private-key',
                                      type=util.Path,
                                      help='Local path to certificate private key')
    action_parser_deploy.add_argument('-c', '--certificate',
                                      type=util.Path,
                                      help='Local path to ssl signed certificate')
    action_parser_deploy.add_argument('--all-servers', action='store_true', default=False,
                                      help='Deploy certificate on all servers rather than just the ones out of synch.')

    return parser.parse_args(args)


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    options = parse_arguments(args=args)

    logger.setLevel(options.debug or logger.level)

    # this is the only action that does not require authentication
    if options.action == "version":
        print(display_version())
        return

    # actions that can be done on multiple blueprints
    if options.action in ['check', 'renew']:

        # build list of all blueprints to process
        blueprints = []
        if options.blueprint.is_file():
            blueprints.append(options.blueprint)
        elif options.blueprint.is_dir():
            for root_path, _, filenames in os.walk(options.blueprint):
                for filename in fnmatch.filter(filenames, '*.yaml'):
                    blueprints.append(util.Path(root_path) / filename)
        else:
            raise IOError("Invalid path specified: '%s'" % options.blueprint)

        # process blueprints 1 by 1
        for blueprint in blueprints:

            my_ssl_manager = manager.SslManager(
                global_config=options.config,
                blueprint_path=blueprint,
                credentials=parse_credentials(
                    cli_credentials=options.credentials,
                    credentials_file=options.credentials_file,
                ),
                staging=options.staging,
            )
            if options.action == 'check':
                logger.info("Processing blueprint %s" % blueprint)
                to_be_renewed, servers_to_update = my_ssl_manager.get_renewal_status()
                if not to_be_renewed and len(servers_to_update) == 0:
                    logger.info("Certificate and all servers up to date for '%s'. Nothing to do.",
                                my_ssl_manager.ssl_blueprint.name)
            elif options.action == 'renew':
                my_ssl_manager.renew(force=options.force)

    # action on a single blueprint
    elif options.action == 'deploy':

        my_ssl_manager = manager.SslManager(
            global_config=options.config,
            blueprint_path=options.blueprint,
            credentials=parse_credentials(
                cli_credentials=options.credentials,
                credentials_file=options.credentials_file
            ),
            staging=options.staging,
        )

        my_ssl_manager.deploy(
            tracking_record_id=options.tracking_record,
            certificate_path=options.certificate,
            private_key_path=options.private_key,
            all_servers=options.all_servers,
        )


def display_version():
    return "Autossl version {version}".format(version=autossl.__version__)


def parse_credentials(cli_credentials, credentials_file):
    """Perform first parsing of input credentials to extract credential name
    rest of the parsing will be done later depending on credential type

    :param cli_credentials: list of raw credentials from command line
    :type cli_credentials: list
    :param credentials_file: path to a local file containing credentials
    :type credentials_file: pathlib.Path or None
    :return: consolidated credentials information from credentials file and command line
    :rtype: dict
    """
    credentials_dict = dict()

    # read first credentials from local credentials file
    if credentials_file and credentials_file.exists():
        credentials_config = configparser.ConfigParser()
        credentials_config.read(str(credentials_file))

        for credential_name in credentials_config.sections():
            credential_parameters_dict = {}
            for credential_parameter in credentials_config.options(credential_name):
                credential_parameters_dict[credential_parameter] = \
                    credentials_config.get(credential_name, credential_parameter)
            # add retrieved credential to global credential dict
            credentials_dict[credential_name] = credential_parameters_dict

    # then override with any command line credential provided
    for cmd_line_credential in cli_credentials:
        # credential name and content is always separated by a ':'
        # other fields can be separated by any other separator specified in global credentials config (default to ':')
        credential_table = cmd_line_credential.split(':', 1)
        name = credential_table[0]
        raw_content = credential_table[1] if len(credential_table) > 1 else None
        credentials_dict[name] = {
            'raw_content': raw_content
        }

    return credentials_dict


if __name__ == '__main__':
    main()
