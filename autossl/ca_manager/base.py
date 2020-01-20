import logging

logger = logging.getLogger(__name__)


class CaManager(object):

    def __init__(self, ca_config, staging=True, storage_api=None, **kwargs):
        """Base instance of interface with CA to deliver signed certificates

        :param ca_config: Certificate Authority configuration instance
        :type ca_config: ssl.CertificateAuthorityConfig
        :param staging: Testing mode. Use staging or test CA instance (when available).
        :type staging: bool
        :param storage_api: storage API instance
        :type storage_api: storage.base.Storage
        """
        self.ca_config = ca_config
        self.staging = staging
        self.storage_api = storage_api

    @property
    def is_automated_renewal_supported(self):
        """Check is current CA supports automated renewal

        :return: True, if this CA implementation supports automated renewal
        :rtype: bool
        """
        return False

    def get_signed_certificate(self, ssl_blueprint=None, csr_path=None, servers_api=None):
        """Get PEM encoded certificate using current Certificate Authority implementation

        :param ssl_blueprint:
        :type ssl_blueprint: ssl.SslBlueprint
        :param csr_path: path to CSR file
        :type csr_path: pathlib.Path
        :param servers_api: list of api instances to each server
        :type servers_api: list(server.base.Server)
        :return: PEM encoded signed certificate as bytes
        :rtype: bytes
        """
        raise NotImplementedError("Method must be overridden in child class")
