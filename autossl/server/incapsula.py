import base64
import datetime
import json
import logging
import time

import requests

from .. import exception, ssl
from . import base

logger = logging.getLogger(__name__)


class IncapsulaSite(base.Server):

    BASE_URL = "https://my.incapsula.com:443"

    def __init__(self, api_key, api_id, site_id, crt_name, **kwargs):
        super(IncapsulaSite, self).__init__(crt_name=crt_name, **kwargs)
        self.api_key = api_key
        self.api_id = api_id
        self.site_id = site_id
        # The certificate must contain the full chain - root CA, intermediate CA, and the origin server certificates.
        # see https://docs.imperva.com/bundle/cloud-application-security/page/more/upload-ssl.htm
        self.deploy_full_chain = True

        # enable retry on :
        # - failed DNS lookups
        # - socket connections
        # - connection timeouts
        # but never to requests where data has made it to the server
        self.session = requests.Session()
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=5))

        # all queries must contain at least this parameters
        self.headers = {'x-API-Key': self.api_key, 'x-API-Id': self.api_id}
        self.basic_params = {'site_id': self.site_id}
        self.site_status = self.session.post(
            url='{}/api/prov/v1/sites/status'.format(self.BASE_URL),
            headers=self.headers,
            data=self.basic_params,
        ).json()

    def get_description(self):
        return "[{} - {} ({})]".format(self.__class__.__name__, self.site_status['domain'], self.site_id)

    def deploy_cert(self, key, cert, **kwargs):
        # authentication data and site ID
        parameters = self.basic_params.copy()

        parameters.update({
            'certificate': base64.b64encode(cert.read_bytes()),
            'private_key': base64.b64encode(key.read_bytes()),
        })

        try:
            json_response = {}
            for _ in range(5):
                json_response = self.session.post(
                    url='{}/api/prov/v1/sites/customCertificate/upload'.format(self.BASE_URL),
                    headers=self.headers,
                    data=parameters,
                ).json()
                # deployment is a success
                if json_response['res'] == 0:
                    break
                # specific behavior for Internal error code, that is returned quite often by Incapsula...
                # => just retry, it generally works fine the 2nd or 3rd time
                elif json_response['res'] == 3015:
                    time.sleep(1)
                    continue
            # no success, just return exception with last error message
            else:
                raise exception.DeployCertificateError('Unable to deploy new certificate on {}: {}'.format(
                    self.get_description(), json.dumps(json_response, indent=4)))

            # Upload successful
            logger.info("Certificate/Key %s updated successfully on %s.", self.crt_name, self.get_description())

        except requests.exceptions.RequestException as ex:
            raise exception.DeployCertificateError(
                msg='Unable to deploy new certificate on {}: {}'.format(self.get_description(), str(ex)),
                original_exception=ex,
            )

    def is_same(self, common_name=None, sans=None, exact_match=False):
        """Check if domain for targeted Incapsula site is part of specified domains

        :param common_name: Common name
        :type common_name: str
        :param sans: list of Subject Alternate Names
        :type sans: list
        :param exact_match: if True, certificate must exactly match input domains
            if False, input domain will also match wildcard certificate and additional domains in certificate will
            be ignored
        :type exact_match: bool
        :return: True if Incapsula site domain is covered by input domains
        """
        blueprint_domains = ssl.get_domains(common_name=common_name, sans=sans)

        # check if Incapsula domain is included in input domains
        for blueprint_domain in blueprint_domains:
            if ssl.is_domain_matching(domain_to_check=self.site_status['domain'],
                                      reference_domain=blueprint_domain,
                                      exact_match=exact_match):
                return True

        return False

    def get_certificate_information(self):
        """Retrieve certificate information from Incapsula site.

        :return: SSL certificate information
        :rtype: autossl.ssl.SslCertificate
        :raise autossl.exception.CertificateNotFound: if certificate does not exist yet on server
        """
        custom_certificate = self.site_status.get('ssl', {}).get('custom_certificate')

        # if invalid incapsula response or no custom_certificate deployed yet
        if self.site_status['res'] != 0 or custom_certificate is None or custom_certificate.get('active') is not True:
            raise exception.CertificateNotFound("No certificate found for site ID {}".format(self.get_description()))

        # Get expiration date (in milliseconds, since 1970) from site configuration
        expiration_date_ms = custom_certificate.get('expirationDate')
        if expiration_date_ms is None:
            raise RuntimeError(
                "Unable to get certificate expiration date (path: ssl.custom_certificate.expirationDate)"
                " for site ID {} in api response {}".format(self.get_description(),
                                                            json.dumps(self.site_status, indent=4))
            )

        return ssl.SslCertificate(
            common_name=self.site_status['domain'],
            sans=[],
            expiration=datetime.datetime.utcfromtimestamp(float(expiration_date_ms)/1000),
        )

    def create_acme_challenge(self, token, key_authorization):
        """Create token on server with specified value

        :param token: challenge key
        :param key_authorization: challenge value
        """
        logger.debug("No challenge to deploy for Incapsula that is just acting as a proxy to real server.")

    def delete_acme_challenge(self, token):
        """Delete challenge created on server

        :param token: challenge key to delete from server
        """
        logger.debug("No challenge to cleanup for Incapsula that is just acting as a proxy to real server.")
