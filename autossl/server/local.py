import logging
import os
import socket

from .. import exception, ssl, util
from . import base

logger = logging.getLogger(__name__)


class LocalServer(base.Server):

    def __init__(self, crt_name, path, acme_dir=None, **kwargs):
        """
        :param crt_name:
        :type crt_name: str
        :param path:
        :type path: pathlib.Path or str
        :param acme_dir:
        :type acme_dir: pathlib.Path or str
        """
        super(LocalServer, self).__init__(crt_name=crt_name, **kwargs)

        if not isinstance(path, util.Path):
            path = util.Path(os.path.expandvars(str(path)))
        self.path = path

        if acme_dir and not isinstance(acme_dir, util.Path):
            acme_dir = util.Path(os.path.expandvars(str(acme_dir)))
        self.acme_dir = acme_dir

    def get_description(self):
        return "[{} - {}:{}]".format(self.__class__.__name__, socket.gethostname(), self.path)

    def deploy_cert(self, key, cert, **kwargs):
        try:
            for source_path, destination_name in [
                (key, self.crt_name + '.key'),
                (cert, self.crt_name + '.crt'),
            ]:
                destination_path = self.path / destination_name
                destination_path.write_bytes(source_path.read_bytes())

            logger.info("Certificate/Key {} updated successfully on {} in {}.".format(
                self.crt_name, self.get_description(), self.path))
        except IOError as ex:
            raise exception.DeployCertificateError(
                msg='Unable to deploy new certificate on {}:{}'.format(self.get_description(), str(ex)),
                original_exception=ex,
            )

    def create_acme_challenge(self, token, key_authorization):
        logger.info("Deploy challenge for token %s" % token)
        wellknown_path = self.acme_dir / token
        wellknown_path.write_bytes(key_authorization.encode('utf-8'))

    def delete_acme_challenge(self, token):
        wellknown_path = self.acme_dir / token
        if wellknown_path.is_file():
            logger.info("Cleanup challenge for token %s" % token)
            wellknown_path.unlink()

    def get_certificate_information(self):
        path = self.path / (self.crt_name + '.crt')
        # certificate is missing on server
        if not path.exists():
            raise exception.CertificateNotFound("Certificate missing on local server at {}".format(path))
        return ssl.SslCertificate(x509_path=path)
