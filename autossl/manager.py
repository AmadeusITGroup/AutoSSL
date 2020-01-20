"""
Script to check and renew automatically SSL certificates on a server
"""
# standard packages
import logging
import os
import shutil
import tempfile
import traceback

# external packages
from six.moves import input
import yaml

# local packages
from . import exception, credential, ssl, util, server, tracking

# list of available apis types
DEFAULT_APIS = ['storage', 'tracking']

# import packages embedded in base module
# external plugins will be imported later and only when/if needed

logger = logging.getLogger(__name__)


class SslManager(object):

    def __init__(self,
                 global_config=None,
                 blueprint_path=None,
                 credentials=None,
                 staging=True):
        """

        :param global_config: local path to global configuration file
        :type global_config: str or None
        :param blueprint_path: SSL blueprint path
        :type blueprint_path: str
        :param staging: Testing mode. Use staging or test server (when available).
        :type staging: bool
        """
        self.ssl_blueprint = ssl.SslBlueprint(global_config_path=global_config, yaml_path=blueprint_path) \
            if blueprint_path or global_config else None
        self.staging = staging
        self.credentials = credentials or {}

        # will be initialized at first use
        self._tracking_api = None
        self._storage_api = None
        self._acme_storage_api = None
        self._ca_manager_api = None

    def __get_credentials_parameters(self, name, parameters):
        self.credentials[name] = credential.get_credentials(
            name=name,
            global_config=self.ssl_blueprint.credentials,
            credentials=self.credentials,
            extra_parameters=parameters,
        )
        return self.credentials[name]

    def get_tracking_api(self):
        return self.__get_api(name='tracking')

    def get_storage_api(self):
        return self.__get_api(name='storage')

    def get_ca_storage_api(self):
        ca_storage_config = None
        # preliminary checks
        if self.ssl_blueprint is not None:
            ca_storage_config = self.ssl_blueprint.ca_config.get_storage_config()
        if ca_storage_config and ca_storage_config.get('type') is not None:
            return self.__get_api(name='ca_storage', api_config=ca_storage_config)
        # by default, use same storage for CA than default storage api
        return self.get_storage_api()

    def get_ca_manager_api(self):
        if self.ssl_blueprint is None:
            raise RuntimeError('No SSL blueprint specified, cannot instantiate CA manager api.')
        ca_config = self.ssl_blueprint.ca_config
        parameters = {
            'parameters': {
                'ca_config': ca_config,
                'storage_api': self.get_ca_storage_api(),
            }
        }
        if ca_config is not None:
            parameters['type'] = ca_config.ca_config.get('type') or 'autossl.ca_manager.base.CaManager'
            if 'parameters' in ca_config.ca_config:
                parameters['parameters'].update(ca_config.ca_config['parameters'])  # add parameters from blueprint
        return self.__get_api(name='ca_manager', api_config=parameters)

    def __get_api(self, name, api_config=None):
        """ dynamically instantiate any api with required parameters

        :param name:
        :return:
        """
        # preliminary checks
        if self.ssl_blueprint is None:
            raise RuntimeError('No SSL blueprint specified, cannot instantiate {} api.'.format(name))
        self_api_name = '_{}_api'.format(name)

        # dynamically set api if not already done
        if not hasattr(self, self_api_name):
            setattr(self, self_api_name, None)

        self_api_config = api_config or getattr(self.ssl_blueprint, name)
        # check first if api has already been instantiated
        if getattr(self, self_api_name) is None:
            dynamic_parameters = dict()
            if self_api_config is not None:
                self_api_config_type = self_api_config['type']
                # add dynamic credentials parameters
                if 'credentials' in self_api_config:
                    dynamic_parameters.update(
                        self.__get_credentials_parameters(
                            name=self_api_config['credentials'],
                            parameters=self_api_config.get('credentials_parameters')
                        )
                    )

                # then update with api server specific parameters from ssl blueprint
                dynamic_parameters.update(self_api_config.get('parameters', {}))
            else:
                # just return base api
                logger.warning("Use of base api as none explicitly specified for %s", name)
                self_api_config_type = 'autossl.{}.base.{}'.format(name, name.title())

            # allow staging mode to be set per api rather than only globally, using api parameters from config file.
            # Default remains global staging flag
            if 'staging' not in dynamic_parameters:
                dynamic_parameters['staging'] = self.staging

            # assigned instantiated api to current instance to reuse it for later calls
            class_ = util.str_to_class(self_api_config_type)
            setattr(self,
                    self_api_name,
                    class_(
                         ssl_blueprint_path=self.ssl_blueprint.consolidated_blueprint_path,
                         **dynamic_parameters)
                    )
        return getattr(self, self_api_name)

    def get_server_api(self, server_parameters):
        # preliminary checks
        if self.ssl_blueprint is None:
            raise RuntimeError('No SSL blueprint specified, cannot instantiate server api.')

        # dynamically instantiate server api with required parameters
        dynamic_parameters = {
            'crt_name': self.ssl_blueprint.name,
            'host': server_parameters.get('host'),
        }

        # add dynamic credentials parameters
        if 'credentials' in server_parameters:
            dynamic_parameters.update(self.__get_credentials_parameters(
                name=server_parameters['credentials'],
                parameters=server_parameters.get('credentials_parameters'),
            ))

        # then update with server parameters
        dynamic_parameters.update(server_parameters.get('parameters', {}))

        # allow staging mode to be set per server rather than only globally, using api parameters from config file.
        # Default remains global staging flag
        if 'staging' not in dynamic_parameters:
            dynamic_parameters['staging'] = self.staging

        class_ = util.str_to_class(server_parameters['type'])
        return class_(
            **dynamic_parameters
        )

    def get_renewal_status(self):
        """Get details status of the certificate for each server from blueprint: expired, modified, missing, ...

        :return: a 2-tuple with (Boolean renewal needed, Array servers to update)
        :rtype: tuple

        The checks performed are the following
         1) it is a new certificate
         2) cert is close to expiration
         3) cert definition has been modified (ex: new san)
         4) new server has been added
        """
        to_be_renewed = False
        servers_to_update = []

        with util.TempDir() as temp_folder:
            try:
                stored_certificate = self.get_certificate_information(working_directory=temp_folder.path)

                if stored_certificate.is_expired(expiration_delay=self.ssl_blueprint.certificate.renewal_delay):
                    to_be_renewed = True
                    logger.info("Certificate expiring soon for '{}'".format(self.ssl_blueprint.name))
                if not stored_certificate.is_same(common_name=self.ssl_blueprint.certificate.common_name,
                                                  sans=self.ssl_blueprint.certificate.sans,
                                                  exact_match=self.ssl_blueprint.certificate.exact_match):
                    to_be_renewed = True
                    logger.info("Certificate definition changed for '{}'".format(self.ssl_blueprint.name))

                # stored certificate does not match blueprint, need renewal in any case
                if to_be_renewed:
                    servers_to_update = self.ssl_blueprint.servers

                # starting here, we know we have a valid certificate in storage
                # we will now check if each server specified in blueprint is up to date
                else:
                    # loop on all servers to check if there is any action to perform
                    for server_config in self.ssl_blueprint.servers:
                        # select proper server api based on server type
                        # and retrieve certificate status directly from servers
                        try:
                            server_api = self.get_server_api(server_parameters=server_config)
                            server_cert = server_api.get_certificate_information()

                            # certificate definition changed
                            # or we have a more recent stored certificate to deploy
                            if not server_api.is_same(
                                    common_name=stored_certificate.common_name,
                                    sans=stored_certificate.sans,
                                    exact_match=self.ssl_blueprint.certificate.exact_match,
                            ) or stored_certificate.expiration > server_cert.expiration:
                                logger.info(
                                    "Stored certificate and server certificate are different for '{}'"
                                    " on server '{}'".format(self.ssl_blueprint.name, server_api.get_description()))
                                servers_to_update.append(server_config)

                        except exception.NotFound:
                            servers_to_update.append(server_config)

            except exception.NotFound:
                to_be_renewed = True
                servers_to_update = self.ssl_blueprint.servers
                logger.info("Certificate '{}' missing".format(self.ssl_blueprint.name))

        return to_be_renewed, servers_to_update

    def renew(self, force=False):
        """Request a renewal and proceed with automated renewal right after (if applicable)

        :param force: request renewal even if not needed
        :type force: bool
        """
        if self.request_renewal(force=force) is True:
            self.renew_certificate()

    def request_renewal(self, force=False):
        """Request renewal of the certificate for specified blueprint

        it is first checking that a renewal is needed.
        Then it is generating a new CSR for the specified blueprint.
        A new tracking record is created with CSR and blueprint attached
        If automated renewal is supported, certificate is generated automatically with CA and attached to TR
        Else, TR is simply sent to 'SSL Certificate Service' team

        :param force: request renewal even if not needed
        :type force: bool
        :return: True if a renewal is needed
        :rtype: bool
        """
        logger.info("Processing blueprint {}".format(self.ssl_blueprint.blueprint_path))
        to_be_renewed = False
        servers_to_update = []

        if force:
            logger.info("Force renewal for '{}'".format(self.ssl_blueprint.name))
            to_be_renewed = True
            servers_to_update = self.ssl_blueprint.servers
        else:
            to_be_renewed, servers_to_update = self.get_renewal_status()
            if not to_be_renewed and len(servers_to_update) == 0:
                logger.info("Certificate and all servers up to date for '{}'. Nothing to do.".format(
                    self.ssl_blueprint.name))
                return False

        if not force:
            if input('Continue ? (y/n)').lower() not in ['y', 'yes']:
                logger.info("Skip renewal...")
                return False

        # no valid certificate, request a new one
        if to_be_renewed:
            logger.info("Start renewal process for certificate '{}'".format(self.ssl_blueprint.name))

            content_name = self.ssl_blueprint.name
            with util.TempDir() as temp_folder:
                key_content = None
                # if reuse of private key is enabled
                # check if it is already existing for this certificate and retrieve it
                if self.ssl_blueprint.certificate.private_key_reuse is True:
                    try:
                        key_content = self.get_storage_api().retrieve_data(
                            name='{}.{}'.format(content_name, ssl.DataType.PrivateKey.value),
                            data_type=ssl.DataType.PrivateKey,
                        )
                    except exception.NotFound:
                        # else a new one will be created automatically
                        pass

                # extract optional organization parameters
                organization_parameters = self.ssl_blueprint.certificate.organization or {}

                # create CSR (and optionally new private key if not retrieved from secret server)
                key_content, csr_path = ssl.generate_csr(name=self.ssl_blueprint.name,
                                                         common_name=self.ssl_blueprint.certificate.common_name,
                                                         sans=self.ssl_blueprint.certificate.sans,
                                                         is_ca=self.ssl_blueprint.certificate.is_ca,
                                                         key_content=key_content,
                                                         key_size=self.ssl_blueprint.certificate.private_key_size,
                                                         output_path=temp_folder.path,
                                                         **organization_parameters)

                # create tracking instance
                tracking_record_id = self.get_tracking_api().create(tracking_type=tracking.base.TrackingType.Renewal)

                # update storage api with tracking record
                self.get_storage_api().tracking_record_id = tracking_record_id

                # save all generated data
                self.save_file(
                    file_type=ssl.DataType.Blueprint,
                    file_path=self.ssl_blueprint.consolidated_blueprint_path,
                )
                self.save_file(
                    file_type=ssl.DataType.CertificateSigningRequest,
                    file_path=csr_path,
                )
                self.save_file(
                    file_type=ssl.DataType.PrivateKey,
                    file_content=key_content
                )

        return to_be_renewed

    def renew_certificate(self):
        """Perform automated renewal of the certificate using ACME protocol

        Will interact with the CA to validate ownership of the domains using ACME protocol.
        In case of any error, input TR will be automatically closed as rejected and exception logged in that TR
        In case of success, certificate is directly attached to the TR

        """
        logger.info("Processing blueprint {}".format(self.ssl_blueprint.blueprint_path))

        ca_manager = self.get_ca_manager_api()

        if not ca_manager.is_automated_renewal_supported:
            logger.info('Automated renewal not supported for {}. Nothing more to do.'.format(self.ssl_blueprint.name))
            return

        with util.TempDir() as temp_folder:
            try:
                logger.info("Start renewal process for certificate '{}'".format(self.ssl_blueprint.name))

                ########################

                # retrieve CSR from tracking or storage
                csr_path = self.get_file(file_type=ssl.DataType.CertificateSigningRequest,
                                         file_identifier='{}.{}'.format(self.ssl_blueprint.name,
                                                                        ssl.DataType.CertificateSigningRequest.value),
                                         output_folder=temp_folder.path)

                # instantiate server api for each server of the list
                # authentication for each server will be checked here
                servers_api = []
                for server_config in self.ssl_blueprint.servers:
                    servers_api.append(self.get_server_api(server_parameters=server_config))

                # request CRT to Certificate authority
                signed_crt_content = ca_manager.get_signed_certificate(
                    ssl_blueprint=self.ssl_blueprint,
                    csr_path=csr_path,
                    servers_api=servers_api,
                )

                # save certificate where requested to be used later in deployment
                self.save_file(
                    file_type=ssl.DataType.Certificate,
                    file_content=signed_crt_content
                )

                # notify that automated renewal was successful
                self.get_tracking_api().update(
                    message='Automated certificate generation successful for {}!'.format(self.ssl_blueprint.name))

            except:  # noqa
                # close record as renewal failed
                self.get_tracking_api().close_for_failure(message="Automated renewal failed: \n{}".format(
                    traceback.format_exc()))
                raise

    def deploy_certificate(self, key_path, crt_path, servers_list):
        """Deploy input SSL certificate on servers

        :param key_path: path to private key
            This is optional, if not provided, private key will be automatically retrieved from SecretServer
        :type key_path: pathlib.Path
        :param crt_path: path to certificate
        :type crt_path: pathlib.Path
        :param servers_list: list of server configuration on which to deploy the certificate.
        """

        # keep track of server with error during deployment
        deployment_error_servers = []
        # keep track of which servers have been deploy successfully
        deployment_success_servers = []

        # deploy new KEY + CRT on each server
        for server_config in servers_list:
            # instantiate correct server api based on server config
            server_api = self.get_server_api(server_parameters=server_config)
            crt_path_to_deploy = crt_path
            try:
                # we must deploy full chain of trust on this server
                # so build temp certificate that also contain CA certificate
                if server_api.deploy_full_chain:
                    certificate_content = crt_path.read_bytes()
                    # append full chain of trust to server certificate content
                    for certificate_from_chain in self.ssl_blueprint.get_chain_of_trust():
                        certificate_content += ('\n' + certificate_from_chain).encode('utf-8')
                    # create temp certificate
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_certificate_file:
                        tmp_certificate_file.write(certificate_content)
                        crt_path_to_deploy = util.Path(tmp_certificate_file.name)

                # deploy key/cert on server
                server_api.deploy_cert(
                    key=key_path,
                    cert=crt_path_to_deploy,
                )
                deployment_success_servers.append(server_config)
            except exception.DeployCertificateError as ex:
                logger.error("Error when deploying certificate on {}: {}".format(server_api.get_description(), str(ex)))
                deployment_error_servers.append({'server': server_config, 'error': str(ex)})
            finally:
                # if temp certificate has just been created, clean it here
                if crt_path_to_deploy != crt_path:
                    os.remove(str(crt_path_to_deploy))

        if any(deployment_error_servers):
            self.get_tracking_api().update(
                message='New certificate successfully deployed on the following servers:\n {}\n\n'
                        'but some errors happened during deployment on following servers: {}'.format(
                            yaml.dump(data=deployment_success_servers, indent=2, default_flow_style=False),
                            yaml.dump(data=deployment_error_servers, indent=2, default_flow_style=False))
            )
        else:
            self.get_tracking_api().close_for_success(
                message='New certificate successfully deployed on all servers:\n {}'.format(
                    yaml.dump(data=servers_list, indent=2, default_flow_style=False))
            )

    def get_and_check_artifacts(
            self,
            tracking_record_id=None,
            certificate_path=None,
            private_key_path=None,
            folder=None,
    ):
        """Retrieve currently stored certificate/key and check if valid for deployment

        :param tracking_record_id: tracking record identifier
        :type tracking_record_id: str or None
        :param certificate_path: local path to SSL certificate file. Automatically retrieved if not specified.
        :type certificate_path: pathlib.Path or None
        :param private_key_path: local path to SSL certificate private key. Automatically retrieved if not specified.
        :type private_key_path: pathlib.Path or None
        :param folder: folder where artifacts will be stored.
        :type folder: pathlib.Path or None
        :return: tuple of (certificate path, private key path)
        :rtype: tuple(pathlib.Path, pathlib.Path)
        """
        # create temporary directory to save temporary files
        temp_folder = util.Path(folder or tempfile.mkdtemp())
        try:
            if tracking_record_id:
                # make sure local tracking record is up to date
                self.get_tracking_api().refresh(record_id=tracking_record_id)

            ######################################################################
            # 1. retrieve all needed artifacts
            ######################################################################
            # no certificate in input blueprint (eg: we only got global config information)
            # let's try to retrieve our blueprint from storage/tracking
            if self.ssl_blueprint.certificate is None:
                ssl_blueprint_path = self.get_file(file_type=ssl.DataType.Blueprint,
                                                   file_identifier=self.ssl_blueprint.name,
                                                   output_folder=temp_folder,
                                                   output_filename='%s.yaml' % self.ssl_blueprint.name)

                # we successfully retrieved full blueprint
                # let's refresh local ssl_blueprint from retrieved blueprint
                self.ssl_blueprint = ssl.SslBlueprint(yaml_path=ssl_blueprint_path)
                new_path = temp_folder / os.path.basename('%s.yaml' % self.ssl_blueprint.name)
                ssl_blueprint_path.rename(new_path)
                self.ssl_blueprint = ssl.SslBlueprint(yaml_path=new_path)
            logger.info('Blueprint: %s' % self.ssl_blueprint.blueprint_path.name)

            # certificate file
            certificate_full_path = temp_folder.joinpath('%s.crt' % self.ssl_blueprint.name)
            if certificate_path is not None:
                shutil.copy(str(certificate_path), str(certificate_full_path))
            if certificate_full_path.is_file():
                certificate_path = certificate_full_path
            else:
                certificate_path = self.get_file(
                    file_type=ssl.DataType.Certificate,
                    file_identifier="{}.{}".format(self.ssl_blueprint.name, ssl.DataType.Certificate.value),
                    output_folder=certificate_full_path.parent,
                    output_filename=certificate_full_path.name,
                    # if tracking_id specified, we consider tracking contains the most up to date data
                    # compare to storage so use it as primary source in that case
                    api_names=['tracking', 'storage'] if tracking_record_id else None,
                )
            logger.info('Certificate: %s' % certificate_path.name)

            # private key file
            private_key_full_path = temp_folder.joinpath('%s.key' % self.ssl_blueprint.name)
            if private_key_path is not None:
                # copy file in expected folder and only used temporary folder
                shutil.copy(str(private_key_path), str(private_key_full_path))
            if private_key_full_path.is_file():
                private_key_path = private_key_full_path
            else:
                private_key_path = self.get_file(file_type=ssl.DataType.PrivateKey,
                                                 file_identifier="{}.{}".format(
                                                     self.ssl_blueprint.name, ssl.DataType.PrivateKey.value),
                                                 output_folder=private_key_full_path.parent,
                                                 output_filename=private_key_full_path.name)
            logger.info('PrivateKey: %s' % private_key_path.name)

            ######################################################################
            # 2. perform preliminary checks on certificates before deployment
            ######################################################################
            # check that certificate matches the private key
            if not ssl.check_certificate_with_key(private_key_path, certificate_path):
                raise exception.KeyMismatch('Certificate specified does not match private key')

            # check if certificate can be used, for that use local server to reuse server api
            local_server = server.local.LocalServer(crt_name=self.ssl_blueprint.name, path=temp_folder)

            # check for expiration
            if local_server.is_expired(expiration_delay=self.ssl_blueprint.certificate.renewal_delay):
                raise exception.ExpiredCertificate(
                    "Certificate {} specified is already expired or expiring soon, renewal needed."
                    .format(self.ssl_blueprint.name))

            # check certificate match blueprint
            if not local_server.is_same(
                    common_name=self.ssl_blueprint.certificate.common_name,
                    sans=self.ssl_blueprint.certificate.sans,
                    exact_match=self.ssl_blueprint.certificate.exact_match):
                raise exception.DefinitionMismatch(
                    "Certificate {} specified does matching blueprint, renewal needed.".format(self.ssl_blueprint.name))

            # ensure chain of trust is present if full deploy requested
            full_chain_deploy_requested = any(
                    server_config.get('parameters', {}).get('deploy_full_chain', False)
                    for server_config in self.ssl_blueprint.servers
            )
            chain_of_trust = self.ssl_blueprint.get_chain_of_trust()
            if full_chain_deploy_requested and len(chain_of_trust) == 0:
                raise exception.SslBlueprintInconsistency(
                    "Deployment of full chain requested on a server but missing chain of trust.")

            # check chain of trust is valid if specified
            if len(chain_of_trust) > 0:
                ssl.check_chain_of_trust(chain_of_trust, certificate_full_path)

            return certificate_full_path, private_key_path

        # cleanup temporary files in case of any exception
        except:  # noqa: E722
            # delete folder only if not coming from user input
            if temp_folder.is_dir() and temp_folder != folder:
                shutil.rmtree(str(temp_folder), ignore_errors=True)
            raise

    def deploy(
        self,
        tracking_record_id=None,
        certificate_path=None,
        private_key_path=None,
        all_servers=False
    ):
        """Deploy certificate/key on servers

        if certificate/key file are specified in input, they will be used, else they will be retrieved from configured
        storage.

        If tracking record identifier is specified, certificate can also be retrieved from there, and this record will
        be used to track the change.
        If no tracking record specified, a new one will be created


        :param tracking_record_id: tracking record identifier
        :type tracking_record_id: str
        :param certificate_path: local path to SSL certificate file
        :type certificate_path: pathlib.Path
        :param private_key_path: local path to SSL certificate private key
        :type private_key_path: pathlib.Path
        :param all_servers: if True, deploy certificate/key on all configured servers,
            else only out of synch servers will be updated.
        :type all_servers: bool
        """
        # create temporary directory to save temporary files
        with util.TempDir() as temp_folder:
            ######################################################################
            # 1. retrieve and check all needed artifacts
            ######################################################################
            certificate_path, private_key_path = self.get_and_check_artifacts(
                tracking_record_id=tracking_record_id,
                certificate_path=certificate_path,
                private_key_path=private_key_path,
                folder=temp_folder.path,
            )

            ######################################################################
            # 2. certificate is valid, check where it should be deployed
            ######################################################################
            if all_servers is True:
                servers_to_update = self.ssl_blueprint.servers
            else:
                # check which servers are out of synch, to then deploy where it's needed without touching valid servers
                _, servers_to_update = self.get_renewal_status()

                # all servers are valid, nothing to deploy
                if len(servers_to_update) == 0:
                    logger.info("All servers up to date for certificate '%s'. Nothing to do." % self.ssl_blueprint.name)
                    return

            ######################################################################
            # 3. make sure change is properly tracked
            ######################################################################
            # if no record already specified, we don't want to modify servers without tracking
            # so create new tracking record here
            if tracking_record_id is None:
                tracking_record_id = self.get_tracking_api().create(
                    tracking_type=tracking.base.TrackingType.Synchronize,
                    servers=servers_to_update,
                )

            # update storage api with tracking record
            self.get_storage_api().tracking_record_id = tracking_record_id

            ######################################################################
            # 4. all preliminary checks are successful, start deployment on servers
            ######################################################################
            self.deploy_certificate(
                key_path=private_key_path,
                crt_path=certificate_path,
                servers_list=servers_to_update
            )

    def get_certificate_information(self, working_directory):
        """Retrieve certificate information for the blueprint.

        :param working_directory: directory in which the ssl certificate will be downloaded
        :type working_directory: pathlib.Path
        :return: SSL certificate information
        :rtype: autossl.ssl.SslCertificate
        :raise autossl.exception.NotFound: if certificate does not exist in storage
        """
        path = self.get_file(
            file_type=ssl.DataType.Certificate,
            file_identifier=self.ssl_blueprint.name+'.crt',
            output_folder=working_directory
        )
        return ssl.SslCertificate(x509_path=path)

    def get_file(self, file_type, file_identifier, output_folder, output_filename=None, api_names=None):
        """Retrieve specified stored data

        :param file_type: type of data to retrieve
        :type file_type: ssl.DataType
        :param file_identifier: identifier of the data to retrieve
        :type file_identifier: str
        :param output_folder: which folder content will be written
        :type output_folder: pathlib.Path
        :param output_filename: name of file to write (default: same than 'file_identifier' parameter)
        :type output_filename: str
        :return: local file path to the retrieved content
        :param api_names: list of api in which to search data
        :type api_names: list
        :rtype: pathlib.Path
        """
        output_file_path = output_folder / (file_identifier or output_filename)
        if output_file_path.exists():
            raise IOError("Path already exist {}".format(output_file_path))

        def __get_file_from_api(api_name_, file_type_, file_identifier_, output_file_path_):
            for file_config in self.ssl_blueprint.get_config(name=api_name_, path=['data'], default={}):
                if file_type_ == ssl.DataType(file_config['type']):
                    try:
                        file_content = self.__get_api(name=api_name_).retrieve_data(
                            name=file_identifier_,
                            data_type=file_type_,
                            **file_config.get('parameters', {})
                        )
                        if file_content is None:
                            # don't even try to write file if returned content is None, and keep searching for a match
                            continue
                        output_file_path_.write_bytes(file_content)
                        return True
                    except exception.NotFound:
                        # artifact not found in this api but it may be present in others
                        pass
            return False

        # by default use all apis
        if api_names is None:
            api_names = DEFAULT_APIS

        for api_name in api_names:
            if __get_file_from_api(api_name, file_type, file_identifier, output_file_path):
                break

        # requested data is missing
        if not output_file_path.exists():
            raise exception.NotFound("Requested file '{}' of type {} not found in tracking or storage instances."
                                     .format(file_identifier, file_type.value))

        # make sure file is named as requested in input
        if output_filename:
            output_file_path.rename(output_file_path.parent / output_filename)

        return output_file_path

    def save_file(self, file_type, file_path=None, file_content=None, api_names=None):
        """Save specified content wherever it is configured in blueprint

        :param file_type: type of data to save
        :type file_type: ssl.DataType
        :param file_path: path to a local file to save
        :type file_path: pathlib.Path
        :param file_content: content to save
        :type file_content: bytes
        :param api_names: list of api in which to save data
        :type api_names: list
        :raise IOError: if none of 'file_path' or 'file_content' parameter are specified
        """
        if not (file_path or file_content):
            raise IOError("Either one of 'file_path' or 'file_content' is expected")

        file_name = '{}.{}'.format(self.ssl_blueprint.name, file_type.value)

        # by default use all apis
        if api_names is None:
            api_names = DEFAULT_APIS

        # save all needed data
        for api_name in api_names:
            for file_config in self.ssl_blueprint.get_config(name=api_name, path=['data'], default={}):
                if file_type == ssl.DataType(file_config['type']):
                    self.__get_api(name=api_name).save_data(
                        name=file_name,
                        data_type=file_type,
                        local_path=file_path,
                        content=file_content,
                        **file_config.get('parameters', {})
                    )
                    break
