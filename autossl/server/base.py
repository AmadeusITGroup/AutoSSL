class Server(object):

    def __init__(self, crt_name, deploy_full_chain=False, **kwargs):
        r"""Default server implementation describing interface of a server
        This is an abstract class, so each specialized method must be overridden in parent class.

        :param crt_name: name of certificate on server (without any extension like .crt)
        :type crt_name: str
        :param deploy_full_chain: if True, deploy server certificate with full chain of trust in crt file
            else, simply deploy server certificate in crt file
        :type deploy_full_chain: bool
        """
        self.crt_name = crt_name
        self.deploy_full_chain = deploy_full_chain

    def get_description(self):
        """Get description of this server

        :return: server description
        :rtype: str
        """
        raise NotImplementedError("Must be overridden in parent class")

    def deploy_cert(self, key, cert, **kwargs):
        r"""Deploy input certificate on server

        :param key: path to local private key
        :type key: pathlib.Path
        :param cert: path to local public certificate
        :type cert: pathlib.Path
        :raise exception.DeployCertificateError: if unexpected error occurred during deployment on server
        """
        raise NotImplementedError("Must be overridden in parent class")

    def create_acme_challenge(self, token, key_authorization):
        """Create token on server with specified value

        :param token: challenge key
        :param key_authorization: challenge value
        """
        raise NotImplementedError("Must be overridden in parent class")

    def delete_acme_challenge(self, token):
        """Delete challenge created on server

        :param token: challenge key to delete from server
        :type token: str
        """
        raise NotImplementedError("Must be overridden in parent class")

    def get_certificate_information(self):
        """Retrieve certificate information from server.

        Must be implemented for each type of server.

        :return: SSL certificate information
        :rtype: autossl.ssl.SslCertificate
        :raise autossl.exception.CertificateNotFound: if certificate does not exist yet on server
        """
        raise NotImplementedError("Must be overridden in parent class")

    def is_same(self, common_name=None, sans=None, exact_match=False):
        """Check if current certificate deployed on server is covering all specified domains

        :param common_name: Common name
        :type common_name: str
        :param sans: list of Subject Alternate Names
        :type sans: list
        :param exact_match: if True, certificate must exactly match input domains
            if False, input domain will also match wilcard certificate and additional domains in certificate will
            be ignored
        :type exact_match: bool
        :return: True is certificate is already covering all domains
        """
        return self.get_certificate_information().is_same(common_name, sans, exact_match)

    def is_expired(self, expiration_delay=0):
        """Check for expiration of specified certificate

        :param expiration_delay: Number of days before real expiration we consider a renewal needed
        :type expiration_delay: int
        :return: True is certificate is going to expire in less than expiration_delay days
        :rtype: bool
         """
        return self.get_certificate_information().is_expired(expiration_delay)
