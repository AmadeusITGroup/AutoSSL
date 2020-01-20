from .. import ssl
from . import base


class LocalCa(base.CaManager):
    """Class implementing a certificate authority based on a private key retrieved from CA storage
    """
    def __init__(
            self,
            ca_config,
            staging=True,
            storage_api=None,
            ca_private_key=None,
            ca_certificate=None,
            certificate_validity_days=90,
            **kwargs
    ):
        super(LocalCa, self).__init__(ca_config, staging=staging, storage_api=storage_api)
        self.certificate_validity_days = certificate_validity_days
        self.ca_private_key = self.storage_api.retrieve_data(
            name=ca_private_key,
            data_type=ssl.DataType.PrivateKey,
        )
        self.ca_certificate = self.storage_api.retrieve_data(
            name=ca_certificate,
            data_type=ssl.DataType.Certificate,
        )

    def get_signed_certificate(self, ssl_blueprint=None, csr_path=None, servers_api=None):
        return ssl.sign(
            csr=csr_path.read_bytes(),
            ca_key=self.ca_private_key,
            ca_cert=self.ca_certificate,
            validity_days=self.certificate_validity_days,
        )

    @property
    def is_automated_renewal_supported(self):
        return True
